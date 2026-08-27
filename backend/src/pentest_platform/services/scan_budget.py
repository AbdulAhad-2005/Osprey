"""Scan budget — block full-range / very long work unless explicitly confirmed.

Default elite path: top ports / small ranges / jobs with short scopes.
Full 1-65535 (or equivalent) requires confirm_expensive=true AFTER asking the human.
"""

from __future__ import annotations

import re
from typing import Any

# Tools that commonly waste hours on full ranges
_PORT_SCAN_TOOLS = frozenset(
    {
        "nmap_syn_scan",
        "nmap_service_scan",
        "nmap_custom_scan",
        "rustscan_fast_scan",
        "masscan_high_speed",
        "naabu_port_scan",
        "autorecon_scan",
    }
)

_FULL_PORT_RE = re.compile(
    r"(?i)(?:^|[\s,=])(?:-p\s*)?(?:0-65535|1-65535|-p-|--p-|-p\s*-\b|ports?\s*=\s*1-65535)"
)
_WIDE_RANGE_RE = re.compile(r"(?i)\b(\d{1,5})\s*-\s*(\d{1,5})\b")
_TOP_PORTS_OK = re.compile(r"(?i)--top-ports\s+\d+")
# An explicit "-p <list>" / "--ports <list>" flag — this is how the typed MCP
# layer passes ports (folded into additional_args, not params["ports"]). By
# the point this is checked it has already survived the full-range/wide-range
# gates above, so its presence means a narrow list was in fact given.
_EXPLICIT_PORTS_FLAG_RE = re.compile(r"(?i)(?:^|[\s,])(?:-p|--ports?)\s+[\d][\d,\-]*")

# Soft cap: ranges spanning more than this many ports need confirm.
# Tiered by scanner class — a full SYN sweep of 10k ports is trivial for the
# fast scanners (naabu/rustscan/masscan) and the real IP-ban risk is packet
# RATE (controlled by each tool's rate/ulimit defaults), not port COUNT. Only
# nmap's per-port service/version probing is genuinely slow, so it keeps the
# tight cap. Full 1-65535 / -p- stays blocked for everything (separate gate).
_MAX_PORTS_WITHOUT_CONFIRM = 2000
_FAST_SCANNER_PORT_CAP = 15000
_FAST_SCANNERS = frozenset(
    {"naabu_port_scan", "rustscan_fast_scan", "masscan_high_speed"}
)


def _port_cap_for_tool(tool_name: str, command: str = "") -> int:
    if tool_name in _FAST_SCANNERS:
        return _FAST_SCANNER_PORT_CAP
    cmd = (command or "").strip().lower()
    if cmd.startswith(("masscan", "rustscan", "naabu")):
        return _FAST_SCANNER_PORT_CAP
    return _MAX_PORTS_WITHOUT_CONFIRM


def is_truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in ("1", "true", "yes", "y", "on")


def _estimate_range_span(text: str) -> int | None:
    """Best-effort max span from a-b ranges in a ports string (not a full parser)."""
    best = 0
    for a_s, b_s in _WIDE_RANGE_RE.findall(text or ""):
        try:
            a, b = int(a_s), int(b_s)
        except ValueError:
            continue
        if b < a:
            a, b = b, a
        # Ignore tiny false positives like years in unrelated args
        if b - a + 1 > best:
            best = b - a + 1
    return best or None


def detect_expensive_port_scope(
    *,
    tool_name: str,
    params: dict[str, Any] | None = None,
    additional_args: str = "",
    command: str = "",
) -> str | None:
    """
    Return a human reason if this looks like a full/wide port scan that needs confirm.
    None = OK to run under default budget.
    """
    params = params or {}
    if tool_name not in _PORT_SCAN_TOOLS and not command.strip().startswith(("nmap", "masscan", "rustscan")):
        # Still check shell/script command strings
        if not command and tool_name not in _PORT_SCAN_TOOLS:
            return None

    blob = " ".join(
        [
            str(params.get("ports") or ""),
            str(params.get("flags") or ""),
            str(params.get("extra_args") or ""),
            additional_args or "",
            command or "",
        ]
    )

    if _TOP_PORTS_OK.search(blob) and not _FULL_PORT_RE.search(blob):
        # --top-ports N is the preferred fast path
        m = re.search(r"(?i)--top-ports\s+(\d+)", blob)
        if m and int(m.group(1)) > 5000:
            return (
                f"--top-ports {m.group(1)} is still very heavy. "
                "Prefer --top-ports 1000 (or less), or ask the operator before confirming."
            )
        return None

    if _FULL_PORT_RE.search(blob) or re.search(r"(?i)-p\s*-\b", blob) or "-p-" in blob.replace(" ", ""):
        return (
            "Full TCP port range (1-65535 / -p-) is blocked by default — it often burns "
            "minutes–hours and times out. Prefer ports empty (nmap defaults), "
            "--top-ports 1000, or ports=1-1000 / known opens. "
            "If you truly need full-range: ASK the human operator first, then retry with "
            "confirm_expensive=true."
        )

    span = _estimate_range_span(blob)
    cap = _port_cap_for_tool(tool_name, command)
    if span is not None and span > cap:
        hint = (
            "run it as a background job (platform_job_start) or "
            if tool_name in _FAST_SCANNERS
            else "prefer top-ports / 1-1000 / open ports only. "
        )
        return (
            f"Wide port range (~{span} ports) exceeds the budget for {tool_name or 'this tool'} "
            f"({cap}). {hint}"
            "ASK the operator before full coverage, then retry with confirm_expensive=true."
        )

    # masscan with empty/default historically meant everything — treat missing narrow ports.
    # Check both the typed "ports" param AND an explicit -p/--ports flag already folded
    # into additional_args (how the typed MCP tool actually passes ports for this tool).
    if tool_name == "masscan_high_speed":
        ports = str(params.get("ports") or "").strip()
        has_narrow_ports_param = bool(ports) and ports not in ("1-65535", "0-65535", "-")
        has_explicit_ports_flag = bool(_EXPLICIT_PORTS_FLAG_RE.search(blob))
        if not has_narrow_ports_param and not has_explicit_ports_flag:
            return (
                "masscan without a narrow ports= list is treated as full-range. "
                "Set ports=1-1000 (or a known set). Full range requires operator OK + "
                "confirm_expensive=true."
            )

    return None


def enforce_scan_budget(
    *,
    tool_name: str,
    params: dict[str, Any] | None = None,
    additional_args: str = "",
    command: str = "",
) -> None:
    """Raise ValueError with ask-first guidance unless confirm_expensive is set."""
    params = dict(params or {})
    if is_truthy(params.get("confirm_expensive")):
        return
    reason = detect_expensive_port_scope(
        tool_name=tool_name,
        params=params,
        additional_args=additional_args,
        command=command,
    )
    if reason:
        raise ValueError(reason)


# --- Chunking: the "yes, and here's how" branch of the same decision ---
#
# Deliberately lives here, not a separate module — it reuses _estimate_range_span
# and the same per-tool cap this file already computes for the refusal path.
# Two independent cost models for the same question would drift apart; this is
# the budget gate's alternative action, not a second gate.
#
# Only the slow, per-port-probing scanners actually benefit from chunking —
# the fast scanners (naabu/rustscan/masscan) already handle wide ranges cheaply
# via their own rate control and keep their existing higher cap untouched.
_CHUNKABLE_TOOLS = frozenset({"nmap_syn_scan", "nmap_service_scan", "nmap_custom_scan"})
_CHUNK_SIZE = 1000  # ports per chunk — same order of magnitude as _MAX_PORTS_WITHOUT_CONFIRM
_MAX_CHUNKS = 8  # hard cap so chunking itself can never become the scan explosion it replaces

_PORTS_FLAG_STRIP_RE = re.compile(
    r"(?i)(?:^|\s)(?:-p\s*-|-p\s+[\d,\-]+|--ports?\s+[\d,\-]+)(?=\s|$)"
)


def _strip_ports_flags(text: str) -> str:
    """Remove any -p/-p-/--ports flag from a raw args string, so a freshly
    written params['ports'] is the single, unambiguous port spec once
    command_builder assembles the real command (its own fallback logic only
    honors params['ports'] when -p/--ports isn't already present in args)."""
    return re.sub(r"\s+", " ", _PORTS_FLAG_STRIP_RE.sub(" ", text or "")).strip()


def chunk_port_range(
    *,
    tool_name: str,
    params: dict[str, Any] | None = None,
    additional_args: str = "",
    command: str = "",
) -> list[dict[str, Any]] | None:
    """If this is a wide/full port-range request on a chunkable tool, return a
    list of narrowed params dicts (each independently within budget on its
    own) — None if not wide enough to need chunking, or not a tool this can
    chunk. Caller queues each returned dict as its own job; none of them will
    ever trip enforce_scan_budget, by construction.
    """
    params = dict(params or {})
    if tool_name not in _CHUNKABLE_TOOLS:
        return None

    blob = " ".join(
        [
            str(params.get("ports") or ""),
            str(params.get("flags") or ""),
            str(params.get("extra_args") or ""),
            additional_args or "",
            command or "",
        ]
    )
    if _TOP_PORTS_OK.search(blob) and not _FULL_PORT_RE.search(blob):
        return None  # --top-ports is already narrow by nmap's own default

    cap = _port_cap_for_tool(tool_name, command)

    if _FULL_PORT_RE.search(blob) or "-p-" in blob.replace(" ", ""):
        start, end = 1, 65535
    else:
        span = _estimate_range_span(blob)
        if span is None or span <= cap:
            return None
        match = _WIDE_RANGE_RE.search(blob)
        if not match:
            return None
        a, b = int(match.group(1)), int(match.group(2))
        start, end = (a, b) if a <= b else (b, a)

    total = end - start + 1
    # Chunk SIZE is capped at what would independently pass this tool's own
    # budget when each chunk re-enters enforce_scan_budget on its own — never
    # the other way around (letting size grow to force-fit a chunk COUNT
    # cap would produce chunks that themselves still trip the same gate).
    # If covering the full range at a safe chunk size needs more than
    # _MAX_CHUNKS chunks, this is NOT the "routine wide-range" case chunking
    # exists to dissolve — return None and let the existing refusal +
    # confirm_expensive path handle it, exactly as for a genuine full sweep.
    chunk_span = min(_CHUNK_SIZE, cap)
    n_chunks = -(-total // chunk_span)  # ceil division
    if n_chunks > _MAX_CHUNKS:
        return None

    stripped_args = _strip_ports_flags(additional_args)
    chunks: list[dict[str, Any]] = []
    cur = start
    while cur <= end:
        chunk_end = min(cur + chunk_span - 1, end)
        chunk_params = dict(params)
        chunk_params["ports"] = f"{cur}-{chunk_end}"
        chunk_params["_additional_args_override"] = stripped_args
        chunks.append(chunk_params)
        cur = chunk_end + 1
    return chunks
