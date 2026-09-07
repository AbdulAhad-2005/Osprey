"""Shared nmap command-building helpers (not an MCP tool — underscore-prefixed).

Used by all four nmap wrappers (nmap_syn_scan, nmap_service_scan,
nmap_custom_scan, nmap_full_port_scan). Previously this logic lived only in
the backend's `command_builder.py`, reachable exclusively through the
docker-exec fast path — which is why nmap was the one tool that didn't work
in native/no-Docker mode (every other tool is a normal harvested wrapper
using `_core.runner.run_tool`; nmap alone was special-cased). Moved here so
nmap goes through the exact same path as everything else, in every execution
mode, with one implementation instead of two.
"""

from __future__ import annotations

import re
from typing import Any

_WIDE_RANGE_PORT_THRESHOLD = 20_000  # ports; wide enough sweep to need a much longer per-host budget


def normalize_ports_value(ports: str) -> str:
    """Strip a mistaken -p/--ports prefix from a ports parameter value.

    An LLM often passes "-p22,80" or "-p 22,80" or "--ports 80,443" in the
    ports field itself; callers append their own -p flag downstream.
    """
    cleaned = (ports or "").strip()
    if not cleaned:
        return ""
    cleaned = re.sub(r"^--?p(?:orts?)?\s*", "", cleaned, flags=re.I).strip()
    if cleaned.startswith("-"):
        cleaned = cleaned.lstrip("-").strip()
    return cleaned


def normalize_multi_target(target: str) -> str:
    """nmap accepts space-separated hosts; agents often pass a comma list.

    Without this, target="1.2.3.4,5.6.7.8" was handed to nmap as a single
    host arg -> "Failed to resolve" -> 0 hosts scanned, yet the run still
    reported success. Splitting commas into spaces makes multi-host scans
    actually work.
    """
    parts = [p.strip() for p in re.split(r"[,\s]+", target or "") if p.strip()]
    return " ".join(parts)


def normalize_nmap_flags(flags: str, target: str, *, privileged: bool = False) -> str:
    """Ensure container/host-safe defaults and avoid duplicate targets.

    privileged=True means real root is available (docker exec -u 0, or
    `sudo` on a native host): a raw-socket SYN scan is genuinely available,
    so an explicit -sS is kept (never downgraded to -sT) and --unprivileged
    is never added — that flag tells nmap to assume it has no raw-socket
    access, which would silently defeat the privileged scan even with root
    and -sS both present.
    """
    cleaned = flags.strip()
    if target and target in cleaned:
        cleaned = cleaned.replace(target, "").strip()

    if privileged:
        if "-s" not in cleaned:
            cleaned = f"-sS -Pn {cleaned}".strip()
        elif "-Pn" not in cleaned and "-sn" not in cleaned:
            cleaned = f"-Pn {cleaned}".strip()
        return cleaned

    # SYN scan cannot run without root.
    if "-sS" in cleaned:
        cleaned = cleaned.replace("-sS", "-sT")

    if "-s" not in cleaned:
        cleaned = f"-sT -Pn --unprivileged {cleaned}".strip()
    elif "-Pn" not in cleaned and "-sn" not in cleaned:
        cleaned = f"-Pn {cleaned}".strip()

    if "--unprivileged" not in cleaned and "-sU" not in cleaned:
        cleaned = f"--unprivileged {cleaned}".strip()

    return cleaned


def nmap_has_scripts(flags: str) -> bool:
    low = flags.lower()
    if "--script" in low:
        return True
    return bool(re.search(r"(?:^|\s)-sC(?:\s|$)", flags))


def nmap_flags_cover_wide_range(flags: str) -> bool:
    """True when the port selection is (or is close to) the full 65535-port
    space — nmap's own '-p-' shorthand, or an explicit wide numeric range —
    the shapes that legitimately need far longer than a couple of ports do."""
    low = flags.lower()
    if re.search(r"(?:^|\s)-p-(?:\s|$)", low):
        return True
    m = re.search(r"-p\s*([\d,\-]+)", low)
    if not m:
        return False
    total = 0
    for part in m.group(1).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                total += max(0, int(b) - int(a) + 1)
            except ValueError:
                continue
        else:
            total += 1
    return total >= _WIDE_RANGE_PORT_THRESHOLD


def nmap_script_bound_args(existing: str, *, host_timeout: str = "") -> list[str]:
    """Cap NSE so vuln/default scripts cannot hang a host forever.

    Scales to what's actually being asked for (confirmed via the port
    selection, not guessed): a wide/full range gets a much larger budget by
    default, a narrow one keeps the short default — a flat 90s regardless of
    scan shape meant a full -sV -sC -p- sweep against a rate-limited edge
    (CloudFront et al.) got killed with "Host timed out" before producing any
    result, since it legitimately needs far longer than 90s just to get
    through the port sweep. `host_timeout` lets the caller override
    explicitly either way; 'none'/'0'/'unlimited'/'off' drops the flag
    entirely for a genuinely unrestricted run.
    """
    extra_l = existing.lower()
    parts: list[str] = []
    if "--max-retries" not in extra_l:
        parts.extend(["--max-retries", "2"])
    if "--host-timeout" not in extra_l:
        override = (host_timeout or "").strip()
        if override.lower() in ("none", "0", "0s", "unlimited", "off"):
            pass  # explicit opt-out — no host-level cutoff at all
        else:
            value = override or ("3600s" if nmap_flags_cover_wide_range(existing) else "90s")
            parts.extend(["--host-timeout", value])
    if "--script-timeout" not in extra_l:
        parts.extend(["--script-timeout", "300s" if nmap_flags_cover_wide_range(existing) else "20s"])
    return parts


def apply_structural_ports(extra: str, params: dict[str, Any]) -> str:
    """Render params['ports']/params['top_ports'] into a -p/--top-ports flag
    if the caller didn't already put one in `extra` — the single place any
    nmap tool's -p/--top-ports flag gets built, so a typed-tool param and a
    hand-written `extra_args`/`flags` string can never collide into two
    flags for the same thing."""
    extra = (extra or "").strip()
    ports_raw = str(params.get("ports", "") or "").strip()
    top_ports_raw = str(params.get("top_ports", "") or "").strip()
    if ports_raw and "-p" not in extra and "--ports" not in extra:
        ports_clean = normalize_ports_value(ports_raw)
        if ports_clean:
            extra = f"{extra} -p {ports_clean}".strip() if extra else f"-p {ports_clean}"
    elif top_ports_raw and "--top-ports" not in extra and "-p" not in extra:
        extra = f"{extra} --top-ports {top_ports_raw}".strip() if extra else f"--top-ports {top_ports_raw}"
    return extra
