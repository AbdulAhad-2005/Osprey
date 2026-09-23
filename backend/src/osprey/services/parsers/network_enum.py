"""Deterministic stdout parsers for masscan + SMB/AD/NetBIOS enumeration tools.

These tools previously had no registered parser, so their output fell through to
the generic "unparsed observation" bucket — meaning shares, users, domain info,
NetBIOS names and (for masscan) even open ports never became structured facts
and were invisible to the coverage engine and downstream phases. Each parser
here turns the tool's stdout into typed Observations (PORT / SERVICE / SHARE /
ACCOUNT / HOST) with enough detail (ip / hostname / share / permission / user /
os) for the graph and network-surface tracker to reason about them. Structural
extraction only — nothing here claims impact.
"""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation, ObservationType

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _host_meta(host: str) -> dict:
    """IP vs hostname keying so the network-surface tracker buckets correctly."""
    host = (host or "").strip()
    if not host:
        return {}
    if _IP_RE.fullmatch(host):
        return {"ip": host, "hostname": host}
    return {"hostname": host}


# ---------------------------------------------------------------------------
# masscan — the old parser (parse_rustscan) never matched masscan's format.
# Console:   "Discovered open port 443/tcp on 93.184.216.34"
# -oG/list:  "Host: 1.2.3.4 () Ports: 80/open/tcp//http//"
# ---------------------------------------------------------------------------

_MASSCAN_CONSOLE_RE = re.compile(
    r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_MASSCAN_GREP_RE = re.compile(
    r"Host:\s*(\d{1,3}(?:\.\d{1,3}){3}).*?Ports:\s*(.+)$", re.IGNORECASE
)
_MASSCAN_PORTLIST_RE = re.compile(r"(\d+)/open/(tcp|udp)")


def parse_masscan(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()

    def _emit(ip: str, port: str, proto: str) -> None:
        key = (ip, port)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.PORT,
                target=ip or target,
                source_tool="masscan_high_speed",
                details={"ip": ip, "port": port, "protocol": proto, "hostname": ip},
                tags=["masscan"],
            )
        )

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _MASSCAN_CONSOLE_RE.search(line)
        if m:
            port, proto, ip = m.groups()
            _emit(ip, port, proto.lower())
            continue
        g = _MASSCAN_GREP_RE.search(line)
        if g:
            ip, portblob = g.groups()
            for port, proto in _MASSCAN_PORTLIST_RE.findall(portblob):
                _emit(ip, port, proto.lower())
    return out


def digest_masscan(stdout: str, *, max_items: int = 12) -> str:
    pairs: list[str] = []
    for m in _MASSCAN_CONSOLE_RE.finditer(stdout or ""):
        port, proto, ip = m.groups()
        pairs.append(f"{ip}:{port}/{proto.lower()}")
    for g in _MASSCAN_GREP_RE.finditer(stdout or ""):
        ip, portblob = g.groups()
        for port, proto in _MASSCAN_PORTLIST_RE.findall(portblob):
            pairs.append(f"{ip}:{port}/{proto.lower()}")
    unique = list(dict.fromkeys(pairs))
    if not unique:
        return ""
    extra = f" (+{len(unique) - max_items} more)" if len(unique) > max_items else ""
    return f"{len(unique)} masscan open port(s): {', '.join(unique[:max_items])}{extra}"


# ---------------------------------------------------------------------------
# Shared SMB/AD signal extraction (enum4linux, enum4linux-ng, netexec, rpcclient)
# ---------------------------------------------------------------------------

_USER_RE = re.compile(r"user:\[([^\]]+)\](?:\s*rid:\[([^\]]+)\])?", re.IGNORECASE)
_GROUP_RE = re.compile(r"group:\[([^\]]+)\](?:\s*rid:\[([^\]]+)\])?", re.IGNORECASE)
# enum4linux "//host/share" share references and the classic Sharename table row.
_UNC_SHARE_RE = re.compile(r"//[\w.\-]+/([\w.$\-]+)")
_SHARENAME_ROW_RE = re.compile(
    r"^\s*([\w.$\-]+)\s+(Disk|IPC|Printer)\s*(.*)$", re.IGNORECASE
)
_DOMAIN_RE = re.compile(r"(?:Domain(?:\s*Name)?|Workgroup)\s*[:=]\s*([\w.\-]+)", re.IGNORECASE)
_OS_RE = re.compile(r"(?:OS|Operating System|Platform)\s*[:=]\s*(.+)$", re.IGNORECASE)
_SID_RE = re.compile(r"(?:Domain SID|SID)\s*[:=]\s*(S-\d[\d\-]+)", re.IGNORECASE)


def _extract_host_from_stdout(stdout: str, target: str) -> str:
    if target and target.strip():
        return target.strip()
    m = _IP_RE.search(stdout or "")
    return m.group(1) if m else ""


def _smb_observations(
    stdout: str,
    *,
    source_tool: str,
    engagement_id: str,
    run_id: str,
    target: str,
    max_items: int = 40,
) -> list[Observation]:
    host = _extract_host_from_stdout(stdout, target)
    out: list[Observation] = []
    hmeta = _host_meta(host)

    users: list[tuple[str, str]] = []
    groups: list[str] = []
    shares: dict[str, str] = {}
    domain = ""
    os_str = ""
    sid = ""

    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        for m in _USER_RE.finditer(line):
            name = m.group(1).strip()
            if name and name not in {u for u, _ in users}:
                users.append((name, (m.group(2) or "").strip()))
        for m in _GROUP_RE.finditer(line):
            g = m.group(1).strip()
            if g and g not in groups:
                groups.append(g)
        for m in _UNC_SHARE_RE.finditer(line):
            s = m.group(1).strip()
            if s:
                shares.setdefault(s, "")
        row = _SHARENAME_ROW_RE.match(raw)
        if row and row.group(1).lower() not in ("sharename",):
            shares.setdefault(row.group(1).strip(), (row.group(3) or "").strip())
        if not domain:
            dm = _DOMAIN_RE.search(line)
            if dm:
                domain = dm.group(1).strip()
        if not os_str:
            om = _OS_RE.search(line)
            if om and len(om.group(1).strip()) < 120:
                os_str = om.group(1).strip()
        if not sid:
            sm = _SID_RE.search(line)
            if sm:
                sid = sm.group(1).strip()

    # A reachable, enumerable SMB host is itself a SERVICE fact.
    if host and (users or shares or domain or os_str):
        details = {**hmeta, "service": "smb", "port": "445"}
        if domain:
            details["domain"] = domain
        if os_str:
            details["os"] = os_str
        if sid:
            details["domain_sid"] = sid
        details.update({"user_count": len(users), "share_count": len(shares)})
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SERVICE,
                target=host,
                source_tool=source_tool,
                details=details,
                tags=["smb", "enumeration"],
            )
        )

    if os_str and host:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.BANNER,
                target=host,
                source_tool=source_tool,
                details={**hmeta, "os": os_str[:200]},
                tags=["os", "os_detected", "smb"],
            )
        )

    for share, comment in list(shares.items())[:max_items]:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SHARE,
                target=host,
                source_tool=source_tool,
                details={**hmeta, "share": share, "comment": comment},
                tags=["smb", "share"],
            )
        )

    if users:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.ACCOUNT,
                target=host,
                source_tool=source_tool,
                details={
                    **hmeta,
                    "kind": "users",
                    "user_count": len(users),
                    "users": [u for u, _ in users[:50]],
                    "domain": domain,
                },
                tags=["smb", "users", "enumeration"],
            )
        )
    if groups:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.ACCOUNT,
                target=host,
                source_tool=source_tool,
                details={
                    **hmeta,
                    "kind": "groups",
                    "group_count": len(groups),
                    "groups": groups[:50],
                },
                tags=["smb", "groups", "enumeration"],
            )
        )
    return out


def parse_enum4linux(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    return _smb_observations(
        stdout,
        source_tool="enum4linux_scan",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )


def parse_enum4linux_ng(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    return _smb_observations(
        stdout,
        source_tool="enum4linux_ng_advanced",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )


def parse_rpcclient(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    return _smb_observations(
        stdout,
        source_tool="rpcclient_enumeration",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )


# ---------------------------------------------------------------------------
# smbmap — share table with permissions (READ ONLY / READ, WRITE / NO ACCESS)
# ---------------------------------------------------------------------------

_SMBMAP_HOST_RE = re.compile(
    r"\[[+*]\]\s*IP:\s*(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?", re.IGNORECASE
)
_SMBMAP_SHARE_RE = re.compile(
    r"^\s*([\w.$\-]+)\s+(NO ACCESS|READ ONLY|READ,\s*WRITE|WRITE ONLY)\s*(.*)$",
    re.IGNORECASE,
)


def parse_smbmap(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    host = target
    for raw in (stdout or "").splitlines():
        hm = _SMBMAP_HOST_RE.search(raw)
        if hm:
            host = hm.group(1)
            continue
        sm = _SMBMAP_SHARE_RE.match(raw)
        if not sm:
            continue
        share, perm, comment = sm.group(1), sm.group(2).upper(), sm.group(3).strip()
        if share.lower() in ("disk", "----"):
            continue
        writable = "WRITE" in perm
        readable = "READ" in perm
        interesting = writable or (readable and share.upper() not in ("IPC$",))
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SHARE,
                target=host or target,
                source_tool="smbmap_scan",
                details={
                    **_host_meta(host),
                    "share": share,
                    "permission": perm,
                    "writable": writable,
                    "readable": readable,
                    "comment": comment,
                    "interesting": interesting,
                },
                tags=["smb", "share", "smbmap"] + (["writable"] if writable else []) + (["accessible"] if interesting else []),
            )
        )
    return out


# ---------------------------------------------------------------------------
# netexec / nxc — "PROTO ip port HOST [*] <os banner> (name:..) (domain:..) (signing:..)"
# ---------------------------------------------------------------------------

_NXC_BANNER_RE = re.compile(
    r"^(SMB|LDAP|WINRM|SSH|RDP|MSSQL|FTP)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s+\[\*\]\s*(.+)$",
    re.IGNORECASE,
)
_NXC_NAME_RE = re.compile(r"\(name:([^)]*)\)", re.IGNORECASE)
_NXC_DOMAIN_RE = re.compile(r"\(domain:([^)]*)\)", re.IGNORECASE)
_NXC_SIGNING_RE = re.compile(r"\(signing:([^)]*)\)", re.IGNORECASE)
_NXC_SMBV1_RE = re.compile(r"\(SMBv1:([^)]*)\)", re.IGNORECASE)


def parse_netexec(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    for raw in (stdout or "").splitlines():
        m = _NXC_BANNER_RE.match(raw.strip())
        if not m:
            continue
        proto, ip, port, netbios, banner = m.groups()
        name = (_NXC_NAME_RE.search(banner).group(1) if _NXC_NAME_RE.search(banner) else "")
        domain = (_NXC_DOMAIN_RE.search(banner).group(1) if _NXC_DOMAIN_RE.search(banner) else "")
        signing = (_NXC_SIGNING_RE.search(banner).group(1) if _NXC_SIGNING_RE.search(banner) else "")
        smbv1 = (_NXC_SMBV1_RE.search(banner).group(1) if _NXC_SMBV1_RE.search(banner) else "")
        os_str = banner.split("(name:")[0].strip()
        tags = [proto.lower(), "netexec"]
        if str(signing).strip().lower() in ("false", "no", "0"):
            tags.append("signing_disabled")
        if str(smbv1).strip().lower() in ("true", "yes", "1"):
            tags.append("smbv1_enabled")
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SERVICE,
                target=ip or target,
                source_tool="netexec_scan",
                details={
                    "ip": ip,
                    "hostname": name or netbios,
                    "port": port,
                    "protocol": proto.lower(),
                    "service": proto.lower(),
                    "os": os_str[:200],
                    "domain": domain,
                    "netbios": netbios,
                    "smb_signing": signing,
                    "smbv1": smbv1,
                },
                tags=tags,
            )
        )
    return out


# ---------------------------------------------------------------------------
# nbtscan — "1.2.3.4  HOSTNAME  <server>  ..." NetBIOS name table
# ---------------------------------------------------------------------------

_NBTSCAN_ROW_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.\-]+)\\?([\w.\-]*)\s+(.*)$"
)


def parse_nbtscan(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[str] = set()
    for raw in (stdout or "").splitlines():
        m = _NBTSCAN_ROW_RE.match(raw.strip())
        if not m:
            continue
        ip, name = m.group(1), m.group(2)
        if ip in seen or name.upper() in ("IP", "NBT"):
            continue
        seen.add(ip)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=ip or target,
                source_tool="nbtscan_netbios",
                details={"ip": ip, "hostname": name, "netbios": name},
                tags=["netbios", "smb"],
            )
        )
    return out


def _smb_digest(source_tool: str):
    def _d(stdout: str) -> str:
        users = len({m.group(1) for m in _USER_RE.finditer(stdout or "")})
        shares = len(set(_UNC_SHARE_RE.findall(stdout or "")))
        dm = _DOMAIN_RE.search(stdout or "")
        bits = []
        if dm:
            bits.append(f"domain={dm.group(1)}")
        if users:
            bits.append(f"users={users}")
        if shares:
            bits.append(f"shares={shares}")
        return f"{source_tool}: " + "; ".join(bits) if bits else ""

    return _d


def _smbmap_digest(stdout: str) -> str:
    rows = [
        f"{m.group(1)}[{m.group(2).upper()}]"
        for m in (_SMBMAP_SHARE_RE.match(ln) for ln in (stdout or "").splitlines())
        if m and m.group(1).lower() not in ("disk", "----")
    ]
    return f"smbmap: {len(rows)} share(s): {', '.join(rows[:12])}" if rows else ""


def _register() -> None:
    from osprey.services.parsers.registry import (
        register_output_digester,
        register_output_parser,
    )

    register_output_parser("masscan_high_speed", parse_masscan)
    register_output_digester("masscan_high_speed", digest_masscan)
    register_output_parser("enum4linux_scan", parse_enum4linux)
    register_output_digester("enum4linux_scan", _smb_digest("enum4linux"))
    register_output_parser("enum4linux_ng_advanced", parse_enum4linux_ng)
    register_output_digester("enum4linux_ng_advanced", _smb_digest("enum4linux-ng"))
    register_output_parser("rpcclient_enumeration", parse_rpcclient)
    register_output_digester("rpcclient_enumeration", _smb_digest("rpcclient"))
    register_output_parser("smbmap_scan", parse_smbmap)
    register_output_digester("smbmap_scan", _smbmap_digest)
    register_output_parser("netexec_scan", parse_netexec)
    register_output_parser("nbtscan_netbios", parse_nbtscan)


_register()
