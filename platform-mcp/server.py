"""
Platform MCP gateway for OpenCode / Claude Desktop.

Dynamic multi-target: call platform_set_target(domain) when the user names a
target. Each distinct root domain gets its own engagement_id and isolated
Postgres storage. Switching targets in the same chat rebinds automatically.
"""

from __future__ import annotations

import ipaddress
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
from typed_recon_content import register_typed_recon_content_tools
from typed_vuln import register_typed_vuln_tools
from typed_browser import register_typed_browser_tools
from typed_exploit import register_typed_exploit_tools

API_BASE = os.environ.get("PENTEST_API_BASE", "http://localhost:9000").rstrip("/")
QUICK_TIMEOUT = float(os.environ.get("PENTEST_QUICK_TIMEOUT", "60"))
# Long exec/script posts — keep ≥ OpenCode mcp.timeout (ms) / 1000
HTTP_TIMEOUT = float(os.environ.get("PENTEST_HTTP_TIMEOUT", "900"))
SESSION_RUN_ID = os.environ.get("PENTEST_RUN_ID", "") or uuid.uuid4().hex[:12]

# Active session — one engagement per target (domain / IP / CIDR / host)
_SESSION_TARGET = ""
_SESSION_ENGAGEMENT_ID = ""
_SESSION_SWITCH_NOTICE = ""
# Kind + scope of the bound target so the agent picks the right tools (an IP →
# no subdomain enum; a port → scope network/web tools to it). Re-derivable from
# the target string, but held here to surface in every session header.
_SESSION_TARGET_KIND = "domain"
_SESSION_SCOPE = ""

# The binding above is process-local, so an interrupted call that makes the host
# respawn this MCP server drops it → the next tool fails "No active target" and
# forces a re-bind. Mirror it to a small state file (keyed by PENTEST_RUN_ID when
# set, else a shared default) so a respawned process can restore it. Engagements
# are durable + deterministic by target, so restoring a prior binding is safe.
import json as _json
import tempfile as _tempfile

_SESSION_STATE_FILE = os.path.join(
    _tempfile.gettempdir(),
    f"pentest_mcp_session_{os.environ.get('PENTEST_RUN_ID', '') or 'default'}.json",
)


def _persist_session() -> None:
    try:
        with open(_SESSION_STATE_FILE, "w", encoding="utf-8") as fh:
            _json.dump(
                {
                    "target": _SESSION_TARGET,
                    "engagement_id": _SESSION_ENGAGEMENT_ID,
                    "kind": _SESSION_TARGET_KIND,
                    "scope": _SESSION_SCOPE,
                },
                fh,
            )
    except Exception:  # noqa: BLE001
        pass


def _restore_session() -> bool:
    """Reload a persisted binding into the globals after a process respawn.
    Returns True if a binding was restored. Best-effort."""
    global _SESSION_TARGET, _SESSION_ENGAGEMENT_ID, _SESSION_TARGET_KIND, _SESSION_SCOPE
    try:
        with open(_SESSION_STATE_FILE, encoding="utf-8") as fh:
            data = _json.load(fh)
    except Exception:  # noqa: BLE001
        return False
    tgt = (data.get("target") or "").strip()
    eid = (data.get("engagement_id") or "").strip()
    if not tgt or not eid:
        return False
    _SESSION_TARGET = tgt
    _SESSION_ENGAGEMENT_ID = eid
    _SESSION_TARGET_KIND = data.get("kind") or "domain"
    _SESSION_SCOPE = data.get("scope") or ""
    _log(f"restored session binding {eid} for target {tgt} after process respawn")
    return True

# Section-level context delta — collapse LARGE, slow-changing context sections to
# a one-line placeholder when their rendered content is byte-identical to the
# previous platform_context call for the same engagement. Without this, a mode-1
# MCP-client agent re-reads ~1.5k tokens of unchanged network-surface / attack-
# tree / findings / role-guidance / skills text on every single context call.
# Short decision-driving blocks (gaps, thinking, dispatch, coverage, delta, jobs)
# are always shown in full. Pass full=true to platform_context to expand all.
_CTX_SECTION_CACHE: dict[str, dict[str, str]] = {}
_CTX_COLLAPSIBLE = frozenset(
    {
        "crown_jewels",
        "recent_artifacts",
        "phase_readiness",
        "network_surface",
        "attack_surface_tree",
        "findings_brief",
        "role_guidance",
        "skills_index",
    }
)


def _ctx_delta(eid: str, name: str, text: str, *, full: bool, label: str = "") -> str:
    """Return text, or a one-line placeholder if this collapsible section is
    unchanged since the previous context call for this engagement."""
    if not eid or full or name not in _CTX_COLLAPSIBLE:
        if eid:
            _CTX_SECTION_CACHE.setdefault(eid, {})[name] = text
        return text
    cache = _CTX_SECTION_CACHE.setdefault(eid, {})
    prev = cache.get(name)
    cache[name] = text
    if prev is not None and prev == text:
        return f"_{label or name}: unchanged since last context — pass full=true to expand_"
    return text

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

mcp = FastMCP("osprey")


_QUIET = os.environ.get("PENTEST_MCP_QUIET", "").strip().lower() in ("1", "true", "yes")


def _log(msg: str) -> None:
    """Debug trace — written for an MCP host's own hidden stderr log stream.
    A caller that renders its own interactive output (the CLI) sets
    PENTEST_MCP_QUIET so this doesn't also land in a live terminal."""
    if _QUIET:
        return
    print(f"[osprey-mcp] {msg}", file=sys.stderr, flush=True)


def _normalize_target(raw: str) -> str:
    """Light normalization. The backend analyze-target is the authority and
    returns a canonical engagement key; this just tidies a directly-supplied
    value without corrupting IPs/CIDRs (never split a CIDR mask off)."""
    value = (raw or "").strip().lower().rstrip(".")
    # A CIDR or bare IP is already canonical — return as-is.
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if value.startswith("http://") or value.startswith("https://"):
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    return value


def _valid_target(value: str) -> bool:
    """Accept anything scannable as an engagement key: domain, IPv4/IPv6, or CIDR.
    (host:port is not a key — the backend strips the port to a bare host first.)"""
    if not value:
        return False
    if _DOMAIN_RE.match(value):
        return True
    try:
        ipaddress.ip_network(value, strict=False)  # covers bare IP + CIDR (v4/v6)
        return True
    except ValueError:
        return False


def _get(path: str, *, params: dict[str, Any] | None = None, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    with httpx.Client(base_url=API_BASE, timeout=timeout) as client:
        resp = client.get(path, params=params or {})
        resp.raise_for_status()
        return resp.json()


def _post(path: str, body: dict[str, Any] | list[Any], *, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
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


def _bind_target(target: str, *, force_new: bool = False, kind: str = "domain", scope: str = "") -> dict[str, Any]:
    """Bind session to a target key (domain / IP / CIDR). Ambiguous bare labels
    must be clarified first via analyze-target."""
    global _SESSION_TARGET, _SESSION_ENGAGEMENT_ID, _SESSION_SWITCH_NOTICE
    global _SESSION_TARGET_KIND, _SESSION_SCOPE

    normalized = _normalize_target(target)
    if not _valid_target(normalized):
        raise ValueError(
            f"Incomplete or invalid target {target!r}. Provide a domain, IP, CIDR, "
            "host:port, or URL (or clarify an ambiguous name via analyze-target)."
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
    _SESSION_TARGET_KIND = kind or "domain"
    _SESSION_SCOPE = scope or ""
    _ensure_run_registered(_SESSION_ENGAGEMENT_ID)
    _persist_session()

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
        # A respawned MCP process starts with empty globals — try restoring the
        # last binding from the state file before giving up, so an interrupted
        # call doesn't force a manual re-bind.
        _restore_session()
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
    target_line = f"target: {tgt}"
    if not pinned and _SESSION_TARGET_KIND and _SESSION_TARGET_KIND != "domain":
        target_line += f"  [kind: {_SESSION_TARGET_KIND}"
        target_line += f"; scope: {_SESSION_SCOPE}]" if _SESSION_SCOPE else "]"
    lines = [
        target_line,
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


def _start_expansion_job(engagement_id: str, run_id: str, *, max_passes: int = 5) -> dict[str, Any]:
    """POST /api/v1/jobs/start with kind=expansion — the BFS engine runs as a
    real background job (job_store.py's existing TOOL/SHELL/SCRIPT dispatch
    mechanism, just one more kind) instead of a blocking call. A single pass
    on a real domain can take minutes; nothing that can run that long should
    ever be a synchronous MCP tool call regardless of client-side timeout —
    that was the actual bug, not the timeout value. Returns immediately with
    a job_id; progress is polled via platform_job_poll, final report via
    platform_job_result."""
    return _post(
        "/api/v1/jobs/start",
        {
            "kind": "expansion",
            "engagement_id": engagement_id,
            "run_id": run_id,
            "max_passes": max_passes,
            "label": f"expand(max_passes={max_passes})",
        },
        timeout=30,
    )


def _render_expansion_report(report: dict[str, Any]) -> str:
    passes = report.get("passes") or []
    if not passes:
        return "Surface expansion: nothing to expand (empty frontier)."

    lines = []
    for p in passes:
        d = p.get("delta") or {}
        titles = p.get("new_finding_titles") or []
        sample = ", ".join(titles[:8]) + (f" (+{len(titles) - 8} more)" if len(titles) > 8 else "")
        lines.append(
            f"Pass {p.get('pass_number')}: {d.get('frontier_processed', 0)} seed(s) -> "
            f"+{d.get('new_nodes', 0)} assets, +{d.get('new_edges', 0)} edges"
            + (f" — new: {sample}" if sample else "")
        )

    stopped = report.get("stopped_reason")
    if stopped == "exhausted":
        lines.append("Surface exhausted (2 consecutive passes with nothing new).")
        next_step = "Safe to move on (network/port depth, or the next phase) — expansion found nothing further."
    else:
        lines.append(f"Stopped at pass cap ({len(passes)}) — surface may still be growing.")
        next_step = "Call platform_expand again to continue expanding."

    cand_count = report.get("new_candidate_count") or 0
    if cand_count:
        samples = "; ".join(report.get("new_candidate_samples") or [])
        lines.append(f"Exploit queue: +{cand_count} new candidate(s) — {samples}")
        next_step += " New exploit candidates surfaced — check platform_exploit_queue."

    lines.append(f"Next: {next_step}")
    return "\n".join(lines)


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
    kind = analysis.get("target_kind") or "domain"
    scope = analysis.get("scope") or ""
    info = _bind_target(domain, force_new=force_new, kind=kind, scope=scope)
    info["target_kind"] = kind
    if scope:
        info["scope"] = scope
    if analysis.get("agent_instruction") and kind != "domain":
        info["guidance"] = analysis["agent_instruction"]
    parts = [_session_header(), _block("Target Bind", info)]
    if info.get("switched"):
        parts.append(
            "## Important\n\n"
            "Target changed — prior findings in this chat were for a different "
            "engagement. Use platform_context for the NEW target only."
        )
    parts.append(
        "Next: platform_pipeline(action='start') returns a ready-to-spawn recon "
        "subagent brief — call it now (no backend key required; you supply the "
        "brain via your own native subagent mechanism)."
    )
    # No auto-fire: platform_set_target only binds. The connecting LLM (this
    # session) decides what runs next — call typed tools directly, or opt
    # into platform_pipeline/platform_spawn_agent/platform_expand explicitly
    # when backend-autonomous help is actually wanted. A prior version of
    # this function auto-started platform_pipeline here, which meant a
    # server-side PhaseAgent tried to run through the BACKEND's own LLM
    # config — a second, usually-unconfigured "brain" that failed opaquely
    # whenever the real driver was an external MCP client (this one) with no
    # reason for the backend to also hold an LLM key. Removed outright rather
    # than made conditional: even when the backend LLM IS configured,
    # silently starting an independent agent that calls tools concurrently
    # with whatever this session is doing is the same "why is it running
    # feroxbuster nobody asked for" problem, just gated on an env var instead
    # of always-on. platform_pipeline/platform_spawn_agent/platform_expand
    # remain fully available — nothing about their capability changed, only
    # whether the platform ever calls them without being asked.
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
def platform_expand(max_passes: int = 5, engagement_id: str = "") -> str:
    """
    Start the BFS surface-expansion engine as a background job: subdomains/
    sisters -> live-host probe -> ports -> tech/CDN -> origin IPs -> the
    comprehensive vuln scan, looping until nothing new turns up or max_passes
    is hit. Deterministic and mechanical — no LLM judgment involved in
    running it. Returns immediately with a job_id — do NOT wait on it.

    A real domain can take minutes per pass; this never blocks the chat.
    Continue other work, then platform_job_poll(job_id, wait_seconds=20) to
    check progress (updated after every pass) or platform_job_result(job_id)
    once complete for the full pass-by-pass report — real new asset names,
    not just counts, plus any new exploit candidates the pass surfaced.

    Not auto-started — call it explicitly when you want the deterministic
    breadth engine (mode=engine / no LLM judgment per step), or to re-check a
    target you've been working for a while (new assets discovered manually
    since the last pass get picked up too).

    engagement_id: optional pin — see platform_exec.
    """
    def _run() -> str:
        eid, tgt = _resolve_engagement(engagement_id)
        job = _start_expansion_job(eid, SESSION_RUN_ID, max_passes=max_passes)
        parts = [
            "### OPERATOR MIRROR — SURFACE EXPANSION (background job)",
            _session_header(eid, tgt),
            f"**job_id:** `{job.get('job_id')}` | **status:** {job.get('status')}",
            job.get("hint") or "",
            "",
            f"Continue other work. platform_job_poll(job_id='{job.get('job_id')}', wait_seconds=20) "
            "for progress, platform_job_result once complete for the full report.",
        ]
        return "\n\n".join(parts)

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
    mode=engine: call platform_set_target, then platform_expand — the
    autonomous trigger-graph pipeline runs to a fixpoint with no LLM
    involvement in individual steps (sisters -> subdomains -> IPs -> CDN/origin
    -> subnet pivot -> ports -> services -> vuln scan -> OSINT). Poll with
    platform_job_poll(wait_seconds=20) and report back once
    platform_job_result shows it's done — don't narrate every pass.
    """
    if not target.strip():
        return (
            "Ask the user for a target (domain or IP) before doing anything else. "
            "Then ask whether they want mode=mcp (LLM-driven, step by step — how this "
            "platform normally works) or mode=engine (autonomous pipeline, no LLM per "
            "step, reports back when the whole recon/network sweep is done)."
        )
    chosen_mode = mode.strip().lower() or "mcp"
    if chosen_mode not in ("mcp", "engine"):
        chosen_mode = "mcp"
    if chosen_mode == "engine":
        return (
            f"Call platform_set_target('{target.strip()}'), then platform_expand() "
            "(defaults are fine unless the user asked for a different max_passes). "
            "Poll with platform_job_poll(job_id=..., wait_seconds=20) until it's done, "
            "then read platform_job_result and summarize what the engine found — don't "
            "drive individual recon tools yourself, the engine already covers that ground."
        )
    return (
        f"Call platform_set_target('{target.strip()}'), then proceed normally — "
        "read what auto-expansion (if any) already surfaced, then drive the rest of "
        "the engagement step by step as usual."
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
        eid, tgt = _resolve_engagement(engagement_id)
        act = (action or "start").strip().lower()
        if act == "status":
            data = _get("/api/v1/pipeline/status", params={"engagement_id": eid}, timeout=15)
        elif act == "stop":
            data = _post("/api/v1/pipeline/stop", {"engagement_id": eid}, timeout=15)
        else:
            data = _post("/api/v1/pipeline/start", {"engagement_id": eid, "run_id": SESSION_RUN_ID}, timeout=30)
        parts = [
            f"### OPERATOR MIRROR — PHASE PIPELINE ({act})",
            _session_header(eid, tgt),
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

    role:  recon | network | vuln | web | exploit | osint | custom
    task:  what this sub-agent should accomplish (free-form)
    scope: optional asset/host/domain to focus on

    Returns a job_id — do NOT wait on it. platform_job_poll for progress,
    platform_findings to build on its results. Bounded by agent concurrency +
    spawn-budget caps; if it says the cap is hit, let one finish first.
    """
    def _run() -> str:
        eid, tgt = _resolve_engagement(engagement_id)
        data = _post(
            "/api/v1/pipeline/spawn-agent",
            {"engagement_id": eid, "run_id": SESSION_RUN_ID, "role": role, "task": task, "scope": scope},
            timeout=30,
        )
        return "\n\n".join([
            f"### OPERATOR MIRROR — SPAWN {role.upper()} AGENT",
            _session_header(eid, tgt),
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


def platform_health(target: str = "") -> str:
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
        if not _SESSION_ENGAGEMENT_ID:
            return (
                "ERROR: No active target. Pass target='example.com' or a short name "
                "like target='zong' (will ask you to clarify), or call platform_set_target."
            )
        return f"{_session_header()}\n\n{health_block}"

    result = _safe(_run)
    if result.startswith("ERROR"):
        return f"{result}\nStart the stack with: docker compose up -d"
    return result


def _fetch_context(engagement_id: str = "", target: str = "", *, full: bool = False) -> str:
    eid = engagement_id or _SESSION_ENGAGEMENT_ID
    tgt = target or _SESSION_TARGET
    data = _get(
        "/api/v1/hybrid/context/auto",
        params={"engagement_id": eid, "seed_target": tgt},
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

    # Crown jewels: top 5 compact
    jewels = data.get("crown_jewels") or []
    jewel_lines = []
    for j in jewels[:5]:
        if isinstance(j, dict):
            jewel_lines.append(
                f"{j.get('asset')} score={j.get('score')} "
                f"({', '.join(str(r) for r in (j.get('reasons') or [])[:3])})"
            )

    idx = data.get("stdout_index") or {}
    idx_text = (idx.get("text") if isinstance(idx, dict) else "") or ""

    # Signal-based dispatch (e.g. "port 445 open -> smb enum").
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

    pipeline_line = (data.get("pipeline_line") or "").strip()
    readiness_text = data.get("phase_readiness_text") or ""

    parts = [_session_header(eid, tgt), f"**Jobs:** {jobs_line}"]
    if pipeline_line:
        parts.append(f"**Pipeline:** {pipeline_line}")
    parts += [
        "**Dispatch signals (from detected tech/ports):**\n"
        + ("\n".join(dispatch_lines) if dispatch_lines else "(none yet)"),
        _block("Context delta", data.get("context_delta") or {}),
        _ctx_delta(
            eid,
            "phase_readiness",
            "**Phase status (conductor):**\n" + (readiness_text or "(no engagement bound)"),
            full=full,
            label="Phase status",
        ),
        _ctx_delta(
            eid,
            "crown_jewels",
            "**Crown jewels (top):**\n" + ("\n".join(jewel_lines) if jewel_lines else "(none yet)"),
            full=full,
            label="Crown jewels",
        ),
        _ctx_delta(
            eid,
            "recent_artifacts",
            "**Recent artifacts:**\n" + (idx_text if idx_text else "(none — run a tool first)"),
            full=full,
            label="Recent artifacts",
        ),
    ]
    # Network surface: short only
    ns = data.get("network_surface_text") or ""
    if ns:
        parts.append(
            _ctx_delta(
                eid,
                "network_surface",
                _block("Network surface", ns[:1500] + ("…" if len(ns) > 1500 else "")),
                full=full,
                label="Network surface",
            )
        )
    # Tree: condensed, capped
    tree = data.get("attack_surface_tree_text") or ""
    if tree:
        parts.append(
            _ctx_delta(
                eid,
                "attack_surface_tree",
                _block("Attack surface (condensed)", tree[:2000] + ("…" if len(tree) > 2000 else "")),
                full=full,
                label="Attack surface (condensed)",
            )
        )
    # Findings: short summary only — full dump on demand via platform_findings
    fs = data.get("findings_summary") or ""
    if fs:
        parts.append(
            _ctx_delta(
                eid,
                "findings_brief",
                _block("Findings (brief)", fs[:1200] + ("…" if len(fs) > 1200 else "")),
                full=full,
                label="Findings (brief)",
            )
        )
    # Role guidance: short operator-mindset reminder — full skill text on demand via platform_skills
    rg = (data.get("role_guidance") or "").strip()
    if rg:
        parts.append(
            _ctx_delta(
                eid,
                "role_guidance",
                _block("Role guidance", rg[:700] + ("…" if len(rg) > 700 else "")),
                full=full,
                label="Role guidance",
            )
        )
    # Skills index: names + paths only — call platform_skills(path=...) to read one in full
    si = (data.get("skills_index") or "").strip()
    if si:
        parts.append(
            _ctx_delta(
                eid,
                "skills_index",
                _block("Skills available", si[:900] + ("…" if len(si) > 900 else "")),
                full=full,
                label="Skills available",
            )
        )

    parts.append(
        "---\n"
        "You decide the next probe. Phase status is evidence-based data, not an order — "
        "recon is always active, vuln/exploit unlock when they have real evidence to work with. "
        "Use platform_tools / platform_skills / platform_findings / platform_artifact "
        "only when you need detail. "
        "platform_graph_link_many (bulk — one call for a whole tool run's relationships) "
        "/ platform_graph_link / platform_tag_asset / platform_script when inventing."
    )
    return "\n\n---\n\n".join(parts)


@mcp.tool()
def platform_context(target: str = "", engagement_id: str = "", full: bool = False) -> str:
    """
    Compact briefing from evidence: phase status, crown jewels, jobs, delta.

    Large, slow-changing sections (network surface, attack-surface tree, findings
    brief, role guidance, skills index, crown jewels) collapse to a one-line
    "unchanged" placeholder when identical to your previous context call, to save
    context. Pass full=true to expand every section.

    Call this not just to plan the next probe, but whenever you're stuck — a
    tool keeps failing, or you're unsure what to try next. Memory may already
    hold the answer.

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
            # A fresh target bind is a first look — always render in full.
            return _fetch_context(full=True)
        eid, tgt = _resolve_engagement(engagement_id)
        return _fetch_context(engagement_id=eid, target=tgt, full=full)

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
    if blast_radius.strip():
        body["blast_radius"] = blast_radius.strip()
    if exploit_candidate_id.strip():
        body["exploit_candidate_id"] = exploit_candidate_id.strip()
    _log(
        f"exec {tool} target={tgt} engagement={eid} "
        f"run={SESSION_RUN_ID} force_refresh={force_refresh}"
    )
    # Buffer must exceed the backend's WHOLE response time, not just the tool's
    # run: a slow tool that hits its own timeout (dnsenum routinely does) then
    # drains partial output + parses + ingests before responding. +60s covers
    # that post-timeout processing so the partial always makes it back.
    data = _post("/api/v1/mcp/execute", body, timeout=timeout_seconds + 60)
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
def platform_finalize_check() -> str:
    """
    The conductor's phase-readiness snapshot — evidence-based, not a gate.

    Call this when you're deciding whether to keep going or wrap up. Shows:
    recon is always the active/first phase; vuln/exploit show whether they've
    unlocked yet (real evidence crossed a threshold — live hosts, services,
    tech, URLs for vuln; vulnerabilities/credentials/secrets for exploit);
    and how many new host/subdomain findings look like they'd be worth
    another recon pass. Purely informational — you decide what to do with it.
    """
    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/phase-readiness",
            params={"engagement_id": _SESSION_ENGAGEMENT_ID},
            timeout=45,
        )
        parts = [
            "### OPERATOR MIRROR — PHASE READINESS",
            _session_header(),
            data.get("text") or _block("phase_readiness", data),
        ]
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_report_outline() -> str:
    """
    Structure a trusted report from memory: Observed / Inferred / Hypotheses /
    Crown jewels + the conductor's phase status. Call before COMPLETE or PARTIAL
    prose. Does not invent findings — only organizes what is stored.
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
def platform_related(limit: int = 20) -> str:
    """
    Read-only cross-finding correlation — candidate relationships from memory.

    Returns HYPOTHESES the platform noticed (hosts on one IP with matching page
    titles, hosts sharing a Set-Cookie domain, hosts with heavy URL fan-out) so
    you don't have to eyeball the whole findings list to spot them. Nothing here
    is written to the graph. Commit the ones you judge real with
    platform_graph_link / platform_tag_asset; ignore the rest. Naturally useful
    right after a batch of findings lands, or before deciding where to dig next.
    """

    def _run() -> str:
        _require_bound_target()
        data = _post("/api/v1/hybrid/correlate", dict(_memory_params()), timeout=45)
        cands = data.get("candidates") or []
        if not cands:
            return f"{_session_header()}\n\nNo cross-finding correlations right now."
        lines: list[str] = []
        for c in cands[: max(1, min(int(limit), 60))]:
            if c.get("kind") == "link":
                lines.append(
                    f"LINK  {c.get('source')} --{c.get('relation')}--> {c.get('target')}  "
                    f"[{c.get('evidence_grade')}, score={c.get('score')}]  {c.get('evidence')}"
                )
            else:
                lines.append(
                    f"TAG   {c.get('asset')}  role={c.get('role')} boost={c.get('boost')}  "
                    f"{c.get('evidence')}"
                )
        return (
            f"{_session_header()}\n\n"
            + "\n".join(lines)
            + f"\n\n_{data.get('note') or ''}_"
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
    Persist ONE conclusion that lives only in your reasoning — not tool output.

    Tool / script / shell output is ingested automatically; do not re-record it
    here (harmless no-op, wasted effort). Use this for what a tool did NOT emit:
    an interpretation you reasoned out (an IP-cluster grouping, a path pattern
    across GAU/wayback runs), a suspicion, a hand-verified fact. For a
    relationship between assets use platform_graph_link_many; for a hypothesis
    use platform_think. Prefer platform_record_findings (bulk) to flush several
    at a checkpoint. If it lives only in your chat answer, it should be here too.

    evidence_grade: observed|inferred|unverified.
    finding_type: url|host|port|service|technology|observation|subdomain|
      vulnerability|credential|secret|http_response|access
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
    Persist MANY reason-only conclusions in one call (bulk platform_record_finding).

    The checkpoint flush: at a query-back breakpoint, drop everything you concluded
    but no tool emitted (interpretations, hand-verified facts) in a single
    round-trip instead of one call per fact. Tool/script/shell output is already
    stored automatically — do not bulk-re-record it. Re-sends merge as extra
    observations (never duplicates, never a loss), so flushing is cheap and safe.

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
            hint = t.get("install_hint") or ""
            if not hint and isinstance(t.get("tool"), dict):
                hint = t["tool"].get("install_hint", "")
            normalized.append(
                {
                    "name": name,
                    "description": (desc or "")[:100],
                    "category": cat,
                    "installed": installed,
                    "install_hint": (hint or "")[:160],
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
            # For a MISSING tool, show how to install it (hexstrike-style) so the
            # operator can answer "what else can I install for Osprey?".
            suffix = ""
            if flag == "MISSING" and t.get("install_hint"):
                suffix = f"  — install: {t['install_hint']}"
            lines.append(f"- [{flag}] {name}  [{cat}]  {desc}{suffix}")
        lines = lines[:120]
        ok_n = sum(1 for ln in lines if ln.startswith("- [OK]"))
        miss_n = sum(1 for ln in lines if ln.startswith("- [MISSING]"))
        readiness = _execution_readiness_line()
        return (
            "### OPERATOR MIRROR — TOOL CATALOG\n"
            f"{_session_header() if _SESSION_ENGAGEMENT_ID else '(bind target optional for catalog)'}\n"
            + (readiness + "\n" if readiness else "")
            + f"Showing {len(lines)} tools (OK={ok_n} MISSING={miss_n})"
            + (f" matching {query!r}" if q else "")
            + "\n[OK] = runnable in your current execution environment; [MISSING] = not "
            "installed there (install per the hint, or `platform_install`, after asking "
            "the user). Compiled scanners are MISSING when no tools container/host tools "
            "are reachable — see README Path A/C.\n\n"
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
        eid, tgt = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/exploit-queue/",
            params={"engagement_id": eid, "limit": limit},
            timeout=30,
        )
        candidates = data if isinstance(data, list) else []
        parts = [
            "### OPERATOR MIRROR — EXPLOIT QUEUE",
            _session_header(eid, tgt),
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
def platform_job_poll(job_id: str = "", engagement_id: str = "", wait_seconds: float = 0) -> str:
    """
    Poll one job (job_id=…) or list all jobs for this engagement (empty job_id).

    Status: queued | running | completed | failed. RUNNING jobs carry a `progress`
    field (the current step, overwritten each update — expansion passes, agent
    tool calls) AND a `results_log` (persistent history — every completed step
    stays, nothing overwritten). For kind=agent (a backend-driven phase agent,
    e.g. from `platform_pipeline`'s auto-executor or `platform_spawn_agent`),
    `results_log` shows each tool call's outcome and preview as it happens —
    genuinely watchable turn-by-turn, not fire-and-forget. Read it instead of
    assuming a running job is a black box.

    wait_seconds (0-60, default 0): long-poll — the call blocks server-side up to
    this long for the job to finish or its progress to change, instead of you
    firing off repeated polls in a tight loop. Pass e.g. 20 when you're going to
    wait on a job anyway; it turns several round-trips into one.

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
        wait = max(0.0, min(float(wait_seconds), 60.0))
        data = _get(f"/api/v1/jobs/{jid}", params={"wait_seconds": wait} if wait else None, timeout=wait + 30)
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
            if job.get("kind") == "expansion":
                # ExpansionReport shape, not ToolExecutionResponse — the generic
                # stdout formatter would print nonsense against these keys.
                parts.append(_render_expansion_report(result))
            elif isinstance(result, dict):
                parts.append(_format_exec_result(result))
            else:
                parts.append(_block("Result", result))
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
    Unrestricted bash inside the Kali container — loops, ;, &&, $(), redirects
    all work (e.g. 'for h in www api dev; do dig +short $h.x.com; done').
    Example: 'nmap -sV -p 80,443 1.2.3.4'. Prefer platform_exec for catalog tools;
    use platform_script for long multi-line scripts.

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

    Empty path → index of `name — description` lines. path='shared/evidence-to-hypothesis.md'
    OR path='evidence-to-hypothesis' (bare skill name) → full text.
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
            "Call platform_skills(path='<name>') for full text.",
        ]
        for it in data.get("skills") or []:
            desc = it.get("description") or it.get("title") or ""
            lines.append(f"- [{it.get('phase')}] {it.get('name') or it.get('path')} — {desc}")
        return "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_propose_skill(
    name: str = "",
    phase: str = "",
    description: str = "",
    content: str = "",
    tags: str = "",
    evidence: str = "",
) -> str:
    """
    Propose a NEW operator-local skill capturing a reusable technique you learned.

    Use this ONLY for genuinely novel, transferable methodology — a bypass/chain/
    playbook that worked and will help on FUTURE targets. NOT for: a merge or
    restatement of existing skills (you can already read several skills at once via
    platform_skills), and NOT for per-target facts (those belong in the engagement
    graph via platform_think / platform_record_finding).

    The proposal is INERT until the operator approves it (it is never auto-active,
    never committed, never shipped). Cite what it worked against in evidence=.

    name= short kebab title · phase= recon|network|web|vuln|exploit|osint|commander|shared
    description= one line (when to use it + what it does) · content= the methodology
    (markdown) · tags= comma-separated · evidence= the engagement facts it's grounded in.
    """
    def _run() -> str:
        body = {
            "name": name.strip(), "phase": phase.strip(), "description": description.strip(),
            "content": content, "evidence": evidence.strip(),
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "engagement_id": _SESSION_ENGAGEMENT_ID or "",
        }
        data = _post("/api/v1/capabilities/learned-skills/propose", body)
        return (
            "### OPERATOR MIRROR — SKILL PROPOSED\n"
            f"id={data.get('id')} slug={data.get('slug')} phase={data.get('phase')}\n"
            f"{data.get('note', '')}\n"
            "It is NOT active yet — tell the user it awaits their approval "
            "(/skill approve <id> in the CLI). Continue the engagement meanwhile."
        )

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


@mcp.tool()
def platform_visualization(
    engagement_id: str = "",
    fmt: str = "mermaid",
    max_nodes: int = 200,
    max_edges: int = 400,
    node_type: str = "",
    exclude_urls: bool = True,
) -> str:
    """
    Attack-surface visualization: Mermaid (renders in markdown), Cytoscape JSON, or attack tree.

    Returns structured graph DATA — not rendered images. Use the data as you like:
    embed the Mermaid block in markdown, feed Cytoscape JSON to a web dashboard,
    or read the attack-tree hierarchy for a structured summary.

    fmt='mermaid' — styled graph TD with severity-coloured nodes (renders natively in
    OpenCode/Claude/IDE markdown previews). fmt='json' — Cytoscape-compatible {nodes,edges}
    for web dashboards. fmt='tree' — hierarchical domain→subdomain→IP→port→service tree.
    max_nodes/max_edges control output size. node_type filters to one asset type (host, subdomain…).
    exclude_urls=True filters static-asset URL noise (/assets/uploads/…).

    Note: graph data reflects what ingestion tools stored — third-party trackers
    (doubleclick.net etc.), parse artifacts ("Console" from js_recon), and duplicate
    type entries (domain+host for same name) come from the ingestion layer.
    Use node_type/host/domain to focus on the real target surface.
    """
    max_nodes = max(10, min(int(max_nodes), 1000))
    max_edges = max(10, min(int(max_edges), 2000))

    def _run() -> str:
        eid, _ = _resolve_engagement(engagement_id)
        data = _get(
            f"/api/v1/engagements/{eid}/visualization",
            params={
                "format": fmt,
                "max_nodes": str(max_nodes),
                "max_edges": str(max_edges),
                "node_type": node_type,
                "exclude_urls": str(exclude_urls).lower(),
            },
            timeout=30,
        )
        fmt = data.get("format", fmt)
        body = data.get("data", "")
        if fmt == "mermaid" and isinstance(body, str):
            return f"{_session_header()}\n\n## Attack Surface (Mermaid)\n\n```mermaid\n{body}\n```"
        return "\n\n".join([_session_header(), _block(f"Visualization ({fmt})", body)])

    return _safe(_run)


@mcp.tool()
def platform_report_data(engagement_id: str = "") -> str:
    """
    Structured report data: metrics, severity breakdown, findings by severity,
    infrastructure notes, and Mermaid topology — everything an LLM needs to
    write a pentest report without guessing.

    Use platform_report_outline for the Observed/Inferred/Hypotheses scaffold.
    Use this tool for the quantitative payload (counts, grades, infra posture).
    """
    def _run() -> str:
        eid, _ = _resolve_engagement(engagement_id)
        data = _get(
            f"/api/v1/engagements/{eid}/report-data",
            timeout=30,
        )
        return "\n\n".join([_session_header(), _block("Report data", data)])

    return _safe(_run)


@mcp.tool()
def platform_handoff(engagement_id: str = "") -> str:
    """
    Complete, self-contained engagement dossier for a downstream agent.

    Everything the next phase (exploitation / post-exploitation) needs, assembled
    from durable memory alone — no prior chat/agent context required: asset
    inventory (ip, ports, services, technologies, waf/cdn/os), credentials/secrets,
    vulnerabilities with evidence grade, entry points, every finding with
    provenance, and the relationship graph. This is the recon→exploit handoff.
    """
    def _run() -> str:
        eid, _ = _resolve_engagement(engagement_id)
        data = _get(f"/api/v1/findings/handoff?engagement_id={eid}", timeout=45)
        return "\n\n".join([_session_header(), _block("Engagement handoff dossier", data)])

    return _safe(_run)


# Typed recon/network/exploit catalog tools (typed schemas for the LLM).
def _typed_execute(
    tool_name: str,
    params: dict[str, Any],
    *,
    additional_args: str = "",
    timeout_seconds: int = 300,
    engagement_id: str = "",
    blast_radius: str = "",
    exploit_candidate_id: str = "",
) -> str:
    return _safe(
        lambda: _execute_catalog_tool(
            tool_name,
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
            engagement_id=engagement_id,
            blast_radius=blast_radius,
            exploit_candidate_id=exploit_candidate_id,
        )
    )


_TYPED_COUNT = register_typed_recon_network_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_COUNT} typed recon/network tools")

_TYPED_TECH_COUNT = register_typed_tech_identification_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_TECH_COUNT} typed tech-identification tools")

_TYPED_OSINT_COUNT = register_typed_osint_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_OSINT_COUNT} typed passive-OSINT tools")

_TYPED_CONTENT_COUNT = register_typed_recon_content_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_CONTENT_COUNT} typed recon-content tools")

_TYPED_VULN_COUNT = register_typed_vuln_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_VULN_COUNT} typed vulnerability-analysis tools")

_TYPED_BROWSER_COUNT = register_typed_browser_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_BROWSER_COUNT} typed browser-automation tools")

_TYPED_EXPLOIT_COUNT = register_typed_exploit_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_EXPLOIT_COUNT} typed exploitation/creds/cloud-exploit tools")

# Optional private-overlay typed tools (e.g. Hawkeye's creds-manager). Absent in
# public Osprey — a missing module is a no-op, not an error.
try:
    from typed_private import register_typed_private_tools  # type: ignore

    _TYPED_PRIVATE_COUNT = register_typed_private_tools(mcp, execute=_typed_execute)
    _log(f"registered {_TYPED_PRIVATE_COUNT} typed private-overlay tools")
except ImportError:
    pass


if __name__ == "__main__":
    _log(f"session run_id={SESSION_RUN_ID} (dynamic target — call platform_set_target first)")
    mcp.run()
