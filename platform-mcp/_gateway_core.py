"""Gateway kernel: session state, engagement resolution, HTTP and
formatting helpers, and the shared FastMCP ``mcp`` instance.

The @mcp.tool / @mcp.prompt functions live in the tools_*.py modules and
register onto this module's ``mcp``; server.py wires everything together."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from contextvars import ContextVar
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = (
    os.environ.get("PENTEST_API_BASE")
    or os.environ.get("API_BASE_URL")
    or f"http://localhost:{os.environ.get('BACKEND_PORT', '9000')}"
).rstrip("/")
QUICK_TIMEOUT = float(os.environ.get("PENTEST_QUICK_TIMEOUT", "60"))
# Long exec/script posts — keep ≥ OpenCode mcp.timeout (ms) / 1000
HTTP_TIMEOUT = float(os.environ.get("PENTEST_HTTP_TIMEOUT", "900"))
_CONFIGURED_RUN_ID = os.environ.get("PENTEST_RUN_ID", "").strip()
SESSION_RUN_ID = _CONFIGURED_RUN_ID or uuid.uuid4().hex[:12]

# Active session — one engagement per target (domain / IP / CIDR / host)
_SESSION_TARGET = ""
_SESSION_ENGAGEMENT_ID = ""
_SESSION_SWITCH_NOTICE = ""
# Every engagement id bound via set_target in THIS process. Once more than one
# has been bound, the ambient "current" session is ambiguous (concurrent chats
# sharing one process, or a sequential target switch), so an UNPINNED stateful
# call is rejected rather than silently routed to whichever was bound last
# (B5.2). The backend itself never uses an ambient — every op takes an explicit
# engagement_id — so pinning makes isolation airtight.
_BOUND_ENGAGEMENTS: set[str] = set()
# Kind + scope of the bound target so the agent picks the right tools (an IP →
# no subdomain enum; a port → scope network/web tools to it). Re-derivable from
# the target string, but held here to surface in every session header.
_SESSION_TARGET_KIND = "domain"
_SESSION_SCOPE = ""

# The binding above is process-local. A host that supplies a unique
# PENTEST_RUN_ID gets crash/respawn persistence for that one session. Processes
# without an explicit run id deliberately do NOT share a fallback state file:
# the old ``..._default.json`` made unrelated MCP clients overwrite and restore
# one another's targets.
import json as _json
import tempfile as _tempfile

_SESSION_STATE_FILE = (
    os.path.join(_tempfile.gettempdir(), f"pentest_mcp_session_{_CONFIGURED_RUN_ID}.json")
    if _CONFIGURED_RUN_ID
    else None
)


@dataclass(frozen=True)
class _EngagementContext:
    """All engagement-scoped values needed by one MCP call."""

    engagement_id: str
    target: str
    run_id: str
    kind: str = "domain"
    scope: str = ""
    pinned: bool = False


_ENGAGEMENT_CACHE: dict[str, dict[str, str]] = {}
_ENGAGEMENT_RUN_IDS: dict[str, str] = {}
_REGISTERED_RUNS: set[tuple[str, str]] = set()
_INVOCATION_ENGAGEMENT: ContextVar[str] = ContextVar("osprey_invocation_engagement", default="")


def _persist_session() -> None:
    if not _SESSION_STATE_FILE:
        return
    try:
        temporary = f"{_SESSION_STATE_FILE}.{os.getpid()}.tmp"
        with open(temporary, "w", encoding="utf-8") as fh:
            _json.dump(
                {
                    "target": _SESSION_TARGET,
                    "engagement_id": _SESSION_ENGAGEMENT_ID,
                    "kind": _SESSION_TARGET_KIND,
                    "scope": _SESSION_SCOPE,
                    "run_id": SESSION_RUN_ID,
                },
                fh,
            )
        os.replace(temporary, _SESSION_STATE_FILE)
    except Exception:  # noqa: BLE001
        pass


def _restore_session() -> bool:
    """Reload a persisted binding into the globals after a process respawn.
    Returns True if a binding was restored. Best-effort."""
    global SESSION_RUN_ID, _SESSION_TARGET, _SESSION_ENGAGEMENT_ID
    global _SESSION_TARGET_KIND, _SESSION_SCOPE
    if not _SESSION_STATE_FILE:
        return False
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
    SESSION_RUN_ID = (data.get("run_id") or _CONFIGURED_RUN_ID or SESSION_RUN_ID).strip()
    _ENGAGEMENT_CACHE[eid] = {
        "target": tgt,
        "kind": _SESSION_TARGET_KIND,
        "scope": _SESSION_SCOPE,
    }
    _ENGAGEMENT_RUN_IDS[eid] = SESSION_RUN_ID
    _BOUND_ENGAGEMENTS.add(eid)
    _log(f"restored session binding {eid} for target {tgt} after process respawn")
    return True


def _clear_persisted_session() -> None:
    if not _SESSION_STATE_FILE:
        return
    try:
        os.unlink(_SESSION_STATE_FILE)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _log(f"session state cleanup warning: {exc}")


def _clear_session(*, engagement_id: str = "") -> None:
    """Clear an ambient binding and every local cache entry that can revive it."""
    global _SESSION_TARGET, _SESSION_ENGAGEMENT_ID, _SESSION_SWITCH_NOTICE
    global _SESSION_TARGET_KIND, _SESSION_SCOPE

    eid = (engagement_id or _SESSION_ENGAGEMENT_ID).strip()
    if eid:
        _ENGAGEMENT_CACHE.pop(eid, None)
        _ENGAGEMENT_RUN_IDS.pop(eid, None)
        _BOUND_ENGAGEMENTS.discard(eid)
        _REGISTERED_RUNS.difference_update(
            {key for key in _REGISTERED_RUNS if key[0] == eid}
        )
        _CTX_SECTION_CACHE.pop(eid, None)
    if not engagement_id or eid == _SESSION_ENGAGEMENT_ID:
        _SESSION_TARGET = ""
        _SESSION_ENGAGEMENT_ID = ""
        _SESSION_SWITCH_NOTICE = ""
        _SESSION_TARGET_KIND = "domain"
        _SESSION_SCOPE = ""
        _clear_persisted_session()

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

# White-label hook (default "osprey" is a no-op): a downstream build like the
# private Ababeel overlay sets OSPREY_MCP_SERVER_NAME to rebrand the server's
# self-reported MCP identity without forking this module — same pattern as
# cli/branding.py and gui/src/lib/brand.ts.
mcp = FastMCP(os.environ.get("OSPREY_MCP_SERVER_NAME", "osprey"))


_QUIET = os.environ.get("PENTEST_MCP_QUIET", "").strip().lower() in ("1", "true", "yes")


_LOG_PREFIX = os.environ.get("OSPREY_MCP_SERVER_NAME", "osprey") + "-mcp"


def _log(msg: str) -> None:
    """Debug trace — written for an MCP host's own hidden stderr log stream.
    A caller that renders its own interactive output (the CLI) sets
    PENTEST_MCP_QUIET so this doesn't also land in a live terminal."""
    if _QUIET:
        return
    print(f"[{_LOG_PREFIX}] {msg}", file=sys.stderr, flush=True)


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


# One shared, pooled client reused across all calls. Opening a fresh
# httpx.Client per call (as before) meant a new TCP connect + teardown every
# tool call; over a long, highly-parallel session that piles up sockets in
# TIME_WAIT and file descriptors, which is a source of "connection closed"
# flakiness under load. httpx.Client is safe to share across FastMCP's worker
# threads, and keep-alive pooling makes repeated calls to the backend cheap.
_HTTP_CLIENT: httpx.Client | None = None


def _client() -> httpx.Client:
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None:
        _HTTP_CLIENT = httpx.Client(
            base_url=API_BASE,
            timeout=QUICK_TIMEOUT,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        )
    return _HTTP_CLIENT


def _get(path: str, *, params: dict[str, Any] | None = None, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    resp = _client().get(path, params=params or {}, timeout=min(float(timeout), HTTP_TIMEOUT))
    resp.raise_for_status()
    return resp.json()


def _post(path: str, body: dict[str, Any] | list[Any], *, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    # Cap to HTTP_TIMEOUT so we never wait forever if caller passes a huge value.
    resp = _client().post(path, json=body, timeout=min(float(timeout), HTTP_TIMEOUT))
    resp.raise_for_status()
    return resp.json()


def _delete(path: str, *, params: dict[str, Any] | None = None, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    resp = _client().delete(path, params=params or {}, timeout=min(float(timeout), HTTP_TIMEOUT))
    resp.raise_for_status()
    if resp.status_code == 204 or not resp.content:
        return {"status": "deleted"}
    return resp.json()



def _new_run_id() -> str:
    global SESSION_RUN_ID
    SESSION_RUN_ID = uuid.uuid4().hex[:12]
    return SESSION_RUN_ID


def _ensure_run_registered(engagement_id: str, run_id: str) -> None:
    key = (engagement_id, run_id)
    if key in _REGISTERED_RUNS:
        return
    try:
        _post(
            f"/api/v1/engagements/{engagement_id}/runs/ensure",
            {"run_id": run_id},
            timeout=10,
        )
        _REGISTERED_RUNS.add(key)
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
    _ENGAGEMENT_CACHE[_SESSION_ENGAGEMENT_ID] = {
        "target": _SESSION_TARGET,
        "kind": _SESSION_TARGET_KIND,
        "scope": _SESSION_SCOPE,
    }
    _ENGAGEMENT_RUN_IDS[_SESSION_ENGAGEMENT_ID] = SESSION_RUN_ID
    _ensure_run_registered(_SESSION_ENGAGEMENT_ID, SESSION_RUN_ID)
    _BOUND_ENGAGEMENTS.add(_SESSION_ENGAGEMENT_ID)
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


def _resolve_engagement(engagement_id_override: str = "") -> _EngagementContext:
    """Resolve one complete engagement context, preferring an explicit pin.

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
    requested = (engagement_id_override or "").strip() or _INVOCATION_ENGAGEMENT.get()
    # "Pinned" means something ACTIONABLE happened — the explicit id actually
    # differs from what the ambient session currently holds. A CLI (or any
    # single-focused-session driver) passes engagement_id= on every call by
    # design (concurrent-chat safety), so bool(requested) alone made this
    # notice fire on nearly every tool result even with zero divergence —
    # pure noise, not signal, in the overwhelmingly common case of one
    # session working one engagement. Only the real case (another chat's
    # platform_set_target has overwritten the shared ambient session out
    # from under this one) is worth an operator's attention.
    pinned = bool(requested) and requested != _SESSION_ENGAGEMENT_ID
    if not requested:
        _require_bound_target()
        if len(_BOUND_ENGAGEMENTS) > 1:
            raise RuntimeError(
                "Ambiguous engagement: this process has bound more than one target, so the "
                "ambient 'current' session can't be trusted (B5.2 — a concurrent chat may have "
                "switched it). Pass engagement_id=<the id platform_set_target returned for YOUR "
                "target> on this call. Bound here: " + ", ".join(sorted(_BOUND_ENGAGEMENTS)) + "."
            )
        requested = _SESSION_ENGAGEMENT_ID

    metadata = _ENGAGEMENT_CACHE.get(requested)
    if metadata is None and requested == _SESSION_ENGAGEMENT_ID and _SESSION_TARGET:
        metadata = {
            "target": _SESSION_TARGET,
            "kind": _SESSION_TARGET_KIND,
            "scope": _SESSION_SCOPE,
        }
        _ENGAGEMENT_CACHE[requested] = metadata
    if metadata is None:
        data = _get(f"/api/v1/engagements/{requested}", timeout=15)
        target = str(data.get("target") or "").strip()
        if not target:
            raise RuntimeError(f"Engagement {requested!r} did not return a target")
        metadata = {
            "target": target,
            "kind": str(data.get("target_kind") or data.get("kind") or "domain"),
            "scope": str(data.get("scope") or ""),
        }
        _ENGAGEMENT_CACHE[requested] = metadata

    run_id = _ENGAGEMENT_RUN_IDS.get(requested)
    if not run_id:
        run_id = SESSION_RUN_ID if requested == _SESSION_ENGAGEMENT_ID else uuid.uuid4().hex[:12]
        _ENGAGEMENT_RUN_IDS[requested] = run_id
    _ensure_run_registered(requested, run_id)
    return _EngagementContext(
        engagement_id=requested,
        target=metadata["target"],
        run_id=run_id,
        kind=metadata.get("kind") or "domain",
        scope=metadata.get("scope") or "",
        pinned=pinned,
    )


def _session_header(context: _EngagementContext | None = None) -> str:
    ctx = context or _resolve_engagement()
    target_line = f"target: {ctx.target}"
    if ctx.kind and ctx.kind != "domain":
        target_line += f"  [kind: {ctx.kind}"
        target_line += f"; scope: {ctx.scope}]" if ctx.scope else "]"
    lines = [
        target_line,
        f"engagement_id: {ctx.engagement_id}",
        f"run_id: {ctx.run_id}",
    ]
    if ctx.pinned:
        lines.append(
            "notice: PINNED via explicit engagement_id= — this call bypassed the "
            f"shared ambient session (ambient session is currently bound to "
            f"target={_SESSION_TARGET!r} engagement_id={_SESSION_ENGAGEMENT_ID!r})."
        )
    elif _SESSION_SWITCH_NOTICE:
        lines.append(f"notice: {_SESSION_SWITCH_NOTICE}")
    return "\n".join(lines)


def _memory_params(context: _EngagementContext | None = None) -> dict[str, str]:
    """Engagement-wide memory reads — omit run_id so graph/findings are not empty."""
    ctx = context or _resolve_engagement()
    return {
        "engagement_id": ctx.engagement_id,
        "seed_target": ctx.target,
    }


def _safe(callable_fn) -> str:
    try:
        return callable_fn()
    except httpx.TimeoutException:
        return (
            "### OPERATOR MIRROR — TIMEOUT\n"
            "success: False\n"
            f"ERROR: Platform request timed out on {API_BASE}.\n"
            "The execution outcome is unknown from this connection. Check durable "
            "run history before repeating the action:\n"
            "- Check platform_jobs for tracked jobs/runs and platform_artifact for "
            "any saved output. A synchronous action may still be running; absence "
            "from the job list does not prove it stopped.\n"
            "- For genuinely long work, start it with platform_job_start instead of a "
            "synchronous call, or retry with a SMALLER scope (one IP, top ports only, "
            "timeout_seconds≤90)."
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
        "Next: read platform_context and platform_pipeline, then call the typed tools "
        "you choose directly. platform_investigation_step/execute is the no-LLM baseline."
    )
    # No auto-fire: platform_set_target only binds. The connecting LLM (this
    # session) decides what runs next — call typed tools directly, or opt
    # into platform_pipeline/platform_spawn_agent explicitly
    # when backend-autonomous help is actually wanted. A prior version of
    # this function auto-started platform_pipeline here, which meant a
    # server-side agent tried to run through the BACKEND's own LLM
    # config — a second, usually-unconfigured "brain" that failed opaquely
    # whenever the real driver was an external MCP client (this one) with no
    # reason for the backend to also hold an LLM key. Removed outright rather
    # than made conditional: even when the backend LLM IS configured,
    # silently starting an independent agent that calls tools concurrently
    # with whatever this session is doing is the same "why is it running
    # feroxbuster nobody asked for" problem, just gated on an env var instead
    # of always-on. platform_pipeline/platform_spawn_agent
    # remain fully available — nothing about their capability changed, only
    # whether the platform ever calls them without being asked.
    return "\n\n".join(parts)
