"""Port- and service-scan parsers (nmap/NSE, rustscan, naabu, autorecon)."""

from __future__ import annotations

import re
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers._capping import cap_with_accounting
from osprey.services.parsers.recon_network._shared import _unparsed_observation
from osprey.services.parsers.recon_network.subdomains import _OS_AGGRESSIVE_RE, _OS_DETAILS_RE, _OS_NO_MATCH_RE, _OS_RUNNING_RE


# --- NSE script output (generic — not hardcoded per script name) -----------
#
# nmap prefixes every NSE script's output with '|', its script-name header at
# ~1-space indent ("| script-name:") and nested content at 2+ spaces
# ("|   State: VULNERABLE"). Two shapes are recognized structurally, script
# name never matters for shape detection:
#   - vulners: CPE-block + tab/space-separated ID/CVSS/url[/*EXPLOIT*] lines.
#   - vulns.lua (the library most maintained vuln-category scripts share):
#     State:/IDs:/Risk factor:/References: keyed block.
# Anything else is captured verbatim as a SCANNER_SIGNAL observation — the
# optional LLM observation-extraction layer (Plan 02 Step 5) is where further
# structuring of an unrecognized shape belongs, not a per-parser hack.
_SCRIPT_HEADER_RE = re.compile(r"^([A-Za-z][\w.\-]*)\s*:\s*(.*)$")
_CPE_HEADER_RE = re.compile(r"^cpe:/\S+", re.IGNORECASE)
_VULNERS_ENTRY_RE = re.compile(
    r"^(?P<id>\S+)\s+(?P<cvss>\d+(?:\.\d+)?)\s+(?P<url>\S+)(?:\s+(?P<exploit>\*EXPLOIT\*))?\s*$"
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_VULN_STATE_RE = re.compile(r"^State:\s*(VULNERABLE|LIKELY VULNERABLE|NOT VULNERABLE)", re.IGNORECASE)
_VULN_IDS_RE = re.compile(r"^IDs?:\s*(.*)$", re.IGNORECASE)
_VULN_RISK_RE = re.compile(r"^Risk factor:\s*(.*)$", re.IGNORECASE)
_VULN_KNOWN_KEY_RE = re.compile(
    r"^(state|ids?|risk factor|disclosure date|references|extra information)\s*:", re.IGNORECASE
)
_RISK_TO_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _severity_for_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _nse_signal(
    *,
    engagement_id: str,
    run_id: str,
    target: str,
    title: str,
    description: str,
    evidence: str,
    claimed_severity: str,
    extracted: bool = False,
    details: dict[str, Any],
    tags: list[str],
) -> Observation:
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.SCANNER_SIGNAL,
        target=target,
        source_tool="nmap_custom_scan",
        details={
            **details,
            "title": title[:300],
            "description": description[:500],
            "evidence": evidence[:800],
            "claimed_severity": claimed_severity,
            "extracted": extracted,
        },
        tags=["nmap_custom_scan", "vuln_scanner", f"claimed_severity:{claimed_severity}"] + tags,
    )


def _process_vulners_block(
    lines: list[str],
    *,
    engagement_id: str,
    run_id: str,
    host: str,
    port: str,
    proto: str,
    service: str,
) -> list[Observation]:
    """vulners.nse: CPE sub-headers, each followed by ID/CVSS/url rows. One
    SCANNER_SIGNAL per row; genuine CVE IDs get details["cve"], other vulners
    cross-references (PACKETSTORM/EDB-ID/etc.) get details["reference_id"]
    so they're never misrepresented as CVEs downstream."""
    cpe_entries: dict[str, list[re.Match]] = {}
    order: list[str] = []
    current_cpe = ""
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if _CPE_HEADER_RE.match(s):
            current_cpe = s.rstrip(":").strip()
            if current_cpe not in cpe_entries:
                cpe_entries[current_cpe] = []
                order.append(current_cpe)
            continue
        match = _VULNERS_ENTRY_RE.match(s)
        if match and current_cpe:
            cpe_entries[current_cpe].append(match)

    observations: list[Observation] = []
    for cpe in order:
        entries = cpe_entries.get(cpe, [])
        if not entries:
            continue
        # Exploit-flagged entries sort first so a cap always keeps them.
        entries.sort(key=lambda m: (0 if m.group("exploit") else 1, -float(m.group("cvss"))))

        def _render(m: re.Match, cpe: str = cpe) -> Observation:
            vid = m.group("id")
            cvss = float(m.group("cvss"))
            is_cve = bool(re.match(r"^CVE-\d{4}-\d{4,7}$", vid, re.IGNORECASE))
            severity = _severity_for_cvss(cvss)
            details: dict = {
                "cvss_score": cvss,
                "cpe": cpe,
                "port": port,
                "protocol": proto,
                "service": service,
                "exploit_available_hint": bool(m.group("exploit")),
            }
            if is_cve:
                details["cve"] = vid.upper()
            else:
                details["reference_id"] = vid
            tags = ["vulners", "nmap_nse"] + ([vid.upper()] if is_cve else []) + (
                ["exploit_hint"] if m.group("exploit") else []
            )
            return _nse_signal(
                engagement_id=engagement_id,
                run_id=run_id,
                target=host,
                title=f"{vid} (CVSS {cvss}) — {service or host}:{port}",
                description=f"vulners CPE match for {cpe}"
                + (" — exploit available" if m.group("exploit") else ""),
                evidence=m.group(0),
                claimed_severity=severity,
                details=details,
                tags=tags,
            )

        observations.extend(
            cap_with_accounting(
                entries,
                max_items=15,
                render=_render,
                tool_name="vulners",
                item_label=f"match for {cpe}",
                engagement_id=engagement_id,
                run_id=run_id,
                target=host,
            )
        )
    return observations


def _process_vulns_lua_block(
    script_name: str,
    lines: list[str],
    *,
    engagement_id: str,
    run_id: str,
    host: str,
    port: str,
    proto: str,
    service: str,
) -> list[Observation] | None:
    """The shared vulns.lua output shape most maintained NSE vuln scripts use
    (smb-vuln-*, http-vuln-*, rdp-vuln-*, ftp-vuln-*, ...) — script-agnostic:
    a State:/IDs:/Risk factor:/References: keyed block. Returns None when the
    block doesn't have this shape at all, so the caller can try another."""
    text_lines = [ln.rstrip() for ln in lines]
    state = None
    state_idx = None
    for i, ln in enumerate(text_lines):
        match = _VULN_STATE_RE.match(ln.strip())
        if match:
            state = match.group(1).upper()
            state_idx = i
            break
    if state is None:
        return None
    if state == "NOT VULNERABLE":
        return []  # recognized shape, explicitly negative — nothing to report

    title = script_name
    for j in range(state_idx - 1, -1, -1):
        cand = text_lines[j].strip()
        if not cand or cand.upper() == "VULNERABLE:" or _VULN_KNOWN_KEY_RE.match(cand):
            continue
        title = cand
        break

    cve_ids: list[str] = []
    risk = ""
    references: list[str] = []
    in_references = False
    for ln in text_lines[state_idx:]:
        s = ln.strip()
        ids_match = _VULN_IDS_RE.match(s)
        if ids_match:
            cve_ids = _CVE_RE.findall(ids_match.group(1))
            in_references = False
            continue
        risk_match = _VULN_RISK_RE.match(s)
        if risk_match:
            risk = risk_match.group(1).strip()
            in_references = False
            continue
        if s.lower().startswith("references"):
            in_references = True
            continue
        if in_references and s.startswith("http"):
            references.append(s)

    severity = _RISK_TO_SEVERITY.get(risk.lower(), "medium")
    details: dict = {
        "port": port,
        "protocol": proto,
        "service": service,
        "nse_script": script_name,
        "vuln_state": state,
        "risk_factor": risk,
        "references": references[:10],
    }
    if cve_ids:
        details["cve"] = cve_ids[0].upper()
        if len(cve_ids) > 1:
            details["cve_all"] = [c.upper() for c in cve_ids]
    tags = ["nmap_nse", script_name] + ([cve_ids[0].upper()] if cve_ids else [])
    return [
        _nse_signal(
            engagement_id=engagement_id,
            run_id=run_id,
            target=host,
            title=f"{title} ({host}:{port})",
            description=f"nmap {script_name}: {state}" + (f", risk {risk}" if risk else ""),
            evidence="\n".join(ln for ln in text_lines if ln.strip()),
            claimed_severity=severity,
            extracted=(state == "VULNERABLE"),
            details=details,
            tags=tags,
        )
    ]


def parse_nmap_text(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    current_host = target
    current_port = ""
    current_proto = ""
    current_service = ""
    # OS-detection (-O/-A) is per-scan-report-block, not per-port — track the
    # best line seen for the CURRENT host and emit once its block ends (a new
    # "Nmap scan report for" line, or end of output).
    os_best: tuple[str, str, str] | None = None  # (text, grade, tag_suffix)
    os_host = current_host

    # NSE script block accumulator — flushed on the next non-'|' line, a new
    # port line, a new host block, or end of output. See the block comment
    # above _SCRIPT_HEADER_RE for why shape (not script name) drives parsing.
    script_name: str | None = None
    script_lines: list[str] = []

    def _flush_os() -> None:
        nonlocal os_best
        if os_best is None or not os_host:
            return
        text, grade, tag_suffix = os_best
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.BANNER,
                target=os_host,
                source_tool="nmap_service_scan",
                details={"os": text[:200], "grade": grade},
                tags=["os", f"os_{tag_suffix}"],
            )
        )
        os_best = None

    def _flush_script() -> None:
        nonlocal script_name, script_lines
        name, lines = script_name, script_lines
        script_name, script_lines = None, []
        if name is None or not any(ln.strip() for ln in lines):
            return
        ctx = dict(
            engagement_id=engagement_id,
            run_id=run_id,
            host=current_host,
            port=current_port,
            proto=current_proto,
            service=current_service,
        )
        if name.lower() == "vulners":
            out.extend(_process_vulners_block(lines, **ctx))
            return
        vulns_result = _process_vulns_lua_block(name, lines, **ctx)
        if vulns_result is not None:
            out.extend(vulns_result)
            return
        # Neither recognized shape — never drop; keep as a raw SCANNER_SIGNAL
        # with the unrecognized script text intact.
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=current_host,
                source_tool="nmap_custom_scan",
                details={
                    "kind": "unrecognized_nse_shape",
                    "title": f"{name} output ({current_host}:{current_port})"[:300],
                    "description": f"Unrecognized NSE script output shape for {name}",
                    "evidence": "\n".join(ln.strip() for ln in lines if ln.strip())[:2000],
                    "port": current_port,
                    "protocol": current_proto,
                    "service": current_service,
                    "nse_script": name,
                },
                tags=["nmap_nse", name],
            )
        )

    for line in stdout.splitlines():
        stripped = line.strip()
        lstripped = line.lstrip()

        if lstripped.startswith("|"):
            after_pipe = lstripped[1:]
            if after_pipe.startswith("_"):
                after_pipe = after_pipe[1:]
            leading = len(after_pipe) - len(after_pipe.lstrip(" "))
            header_match = _SCRIPT_HEADER_RE.match(after_pipe.strip()) if leading <= 1 else None
            if header_match:
                _flush_script()
                script_name = header_match.group(1)
                rest = header_match.group(2).strip()
                script_lines = [rest] if rest else []
            elif script_name is not None:
                script_lines.append(after_pipe)
            continue
        else:
            _flush_script()

        if line.startswith("Nmap scan report for"):
            _flush_os()
            parts = line.split(" for ", 1)
            if len(parts) == 2:
                current_host = parts[1].strip().split()[0]
            os_host = current_host
            current_port = current_proto = current_service = ""
            continue

        os_match = _OS_DETAILS_RE.match(stripped)
        if os_match:
            os_best = (os_match.group(1).strip(), "observed", "detected")
            continue
        if os_best is None or os_best[1] != "observed":
            running_match = _OS_RUNNING_RE.match(stripped)
            if running_match:
                os_best = (running_match.group(1).strip(), "inferred", "detected")
                continue
            agg_match = _OS_AGGRESSIVE_RE.match(stripped)
            if agg_match:
                os_best = (agg_match.group(1).strip()[:200], "inferred", "guessed")
                continue
            if os_best is None and _OS_NO_MATCH_RE.match(stripped):
                os_best = ("no exact OS match (attempted)", "unverified", "unknown")
                continue

        port_match = re.match(
            r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$",
            line.strip(),
        )
        if not port_match:
            continue

        port, proto, state, service = port_match.groups()
        if state != "open":
            current_port = current_proto = current_service = ""
            continue

        svc = service.strip()
        current_port, current_proto, current_service = port, proto, svc
        versionish = bool(re.search(r"\d+\.\d+", svc)) or any(
            k in svc.lower()
            for k in ("openssh", "apache", "microsoft", "nginx", "openssl", "dropbear")
        )
        host_details = {"port": port, "protocol": proto, "service": svc}
        # Prefer IP-ish keys for port-flood detection
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", (current_host or "").split()[0]):
            host_details["ip"] = current_host.split()[0]
        else:
            host_details["hostname"] = current_host

        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SERVICE if versionish else ObservationType.PORT,
                target=current_host,
                source_tool="nmap_service_scan",
                details=host_details,
            )
        )
    _flush_script()
    _flush_os()
    return out


def parse_rustscan(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    for line in stdout.splitlines():
        match = re.search(r"(\d+)/tcp\s+open", line)
        if match:
            port = match.group(1)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.PORT,
                    target=target,
                    source_tool="rustscan_fast_scan",
                    details={
                        "port": port,
                        "protocol": "tcp",
                        "ip": target if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target or "") else "",
                        "hostname": target,
                    },
                )
            )
    return out


def parse_naabu(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """naabu -silent lines: host:port or bare port."""
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = target or ""
        port = ""
        if ":" in line:
            left, right = line.rsplit(":", 1)
            if right.isdigit():
                host = left.strip() or host
                port = right.strip()
        elif line.isdigit():
            port = line
        if not port:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.PORT,
                target=host or target,
                source_tool="naabu_port_scan",
                details={
                    "port": port,
                    "protocol": "tcp",
                    "ip": host if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host or "") else "",
                    "hostname": host,
                },
                tags=["naabu"],
            )
        )
    return out



def parse_autorecon(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """AutoRecon output (its per-service nmap files folded into stdout by the tool
    wrapper) → port/service observations, reusing the nmap parser."""
    observations = parse_nmap_text(
        stdout, engagement_id=engagement_id, run_id=run_id, target=target
    )
    relabeled = [o.model_copy(update={"source_tool": "autorecon_scan"}) for o in observations]
    return relabeled or _unparsed_observation(
        stdout, tool_name="autorecon_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


