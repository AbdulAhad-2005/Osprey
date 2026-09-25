"""Deterministic stdout parsers for recon/network tools.

Structural extraction only — see plans/harness/02-evidence-and-observation-layer.md.
A scanner's own verdict (nmap NSE vulners/vulns.lua, a subdomain-takeover
check, a Shodan CVE tag) becomes a ``SCANNER_SIGNAL`` observation carrying the
claim as a fact ("the scanner said X"), never a judged ``VULNERABILITY``
finding — `confidence_for` (Plan 03) decides what that signal earns.
"""

from __future__ import annotations

import json
import re
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers._capping import cap_with_accounting
from osprey.services.target_utils import looks_like_domain, registrable_apex


def parse_subfinder(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        host = line.strip().lower()
        if not host or host.startswith("#") or " " in host:
            continue
        if "." not in host:
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SUBDOMAIN,
                target=target,
                source_tool="subfinder_scan",
                details={"hostname": host},
            )
        )
    return out


# httpx prints these bracketed markers (instead of a status code) when a
# probe could not connect — they are not technology fingerprints.
_HTTPX_FAILURE_MARKERS = {"failed", "timeout", "err", "error"}


def parse_httpx(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue

        brackets = re.findall(r"\[([^\]]*)\]", text)
        if any(b.strip().lower() in _HTTPX_FAILURE_MARKERS for b in brackets):
            # Connection failed — not a live endpoint, nothing to fingerprint.
            continue

        url_match = re.search(r"https?://\S+", text)
        url = url_match.group(0) if url_match else text.split()[0]

        # With -sc/-title/-td, httpx emits multiple bracket groups
        # (e.g. "[200] [Title] [nginx,PHP]"); tech-detect output is the
        # last one and, unlike a status code, is never purely numeric.
        tech = ""
        for b in reversed(brackets):
            b = b.strip()
            if b and not b.isdigit():
                tech = b
                break

        host = ""
        try:
            host = url.split("//")[-1].split("/")[0].split(":")[0].lower()
        except Exception:
            host = ""

        is_cf = _looks_like_cloudflare(text, tech)
        tags: list[str] = []
        details: dict = {"hostname": host} if host else {}
        details["url"] = url
        if tech:
            details["technology"] = tech
        if is_cf:
            details["is_cloudflare"] = True
            details["waf"] = "cloudflare"
            tags.append("cloudflare")

        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.URL,
                target=url,
                source_tool="httpx_probe",
                details={**details, "raw": text[:500]},
                tags=tags,
            )
        )
        if tech:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.TECHNOLOGY,
                    target=url,
                    source_tool="httpx_probe",
                    details={"name": tech, "hostname": host, "url": url},
                    tags=["cloudflare"] if is_cf else [],
                )
            )
    return out


_CF_RE = re.compile(
    r"cloudflare|cf-ray|cf-cache-status|__cf_bm|cf-mitigated|server:\s*cloudflare",
    re.IGNORECASE,
)


def _looks_like_cloudflare(text: str, tech: str = "") -> bool:
    blob = f"{text} {tech}"
    return bool(_CF_RE.search(blob))


_DH_ROW_RE = re.compile(
    r"^(?P<domain>\S+\.\S+)\s+(?P<method>.+?)\s+(?P<conf>low|medium|high)\s+(?P<live>Yes|No)\s*$"
)
_DHJSON_PREFIX = "# DHJSON "


def _domain_hunter_rows(stdout: str):
    """Yield (domain, method, confidence, live, score, evidence) from the last snapshot.

    Prefer the last ``# DHJSON`` line (including ``[]`` so a filtered-empty
    final result is not overwritten by earlier progress tables). Fall back to
    the last ``=== Findings ===`` table for older output.
    """
    json_blocks: list[list[tuple]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(_DHJSON_PREFIX):
            payload = stripped[len(_DHJSON_PREFIX) :]
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                json_blocks.append([_dh_row_from_dict(item) for item in data if isinstance(item, dict)])
    if json_blocks:
        yield from (row for row in json_blocks[-1] if row is not None)
        return
    yield from _domain_hunter_table_rows(stdout)


def _dh_row_from_dict(row: dict) -> tuple | None:
    raw = str(row.get("domain", "") or "").strip()
    apex = registrable_apex(raw)
    if not apex or not looks_like_domain(apex):
        return None
    live = row.get("live")
    if isinstance(live, str):
        live = live.strip().lower() in {"yes", "true", "1"}
    else:
        live = bool(live)
    conf = str(row.get("confidence", "low") or "low").strip().lower()
    if conf not in ("low", "medium", "high"):
        conf = "low"
    return (
        apex.lower(),
        str(row.get("method", "") or "").strip() or "unknown",
        conf,
        live,
        row.get("score"),
        row.get("evidence") or [],
    )


def _domain_hunter_table_rows(stdout: str):
    """Last findings table, including an empty final ``(none)`` block."""
    last_block: list = []
    block: list = []
    in_findings = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("=== Findings"):
            if in_findings:
                last_block = block
            in_findings = True
            block = []
            continue
        if not in_findings:
            continue
        if stripped.startswith("Wrote ") or (stripped.startswith("===") and not stripped.startswith("=== Findings")):
            continue
        if not stripped or stripped.startswith("Domain ") or stripped == "(none)":
            continue
        match = _DH_ROW_RE.match(stripped)
        if match:
            apex = registrable_apex(match.group("domain"))
            if not apex or not looks_like_domain(apex):
                continue
            block.append(
                (
                    apex.lower(),
                    match.group("method").strip(),
                    match.group("conf"),
                    match.group("live") == "Yes",
                    None,
                    [],
                )
            )
    if in_findings:
        last_block = block
    yield from last_block


def parse_domain_hunter(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[str] = set()
    seed_apex = registrable_apex(target) if target else ""
    for domain, method, conf, live, score, evidence in _domain_hunter_rows(stdout):
        if domain in seen:
            continue
        if seed_apex and domain == seed_apex.lower():
            continue
        seen.add(domain)
        evidence_text = evidence if isinstance(evidence, str) else " | ".join(str(item) for item in evidence if item)
        tags = ["sister_domain", "domain_hunter"]
        details: dict[str, Any] = {
            "hostname": domain,
            "method": method,
            "hunter_confidence": conf,
            "live": live,
            "role": "sister_domain",
        }
        if score is not None:
            details["score"] = score
        if evidence:
            details["hunter_evidence"] = evidence
            details["evidence_text"] = evidence_text
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target,
                source_tool="domain_hunter",
                details=details,
                tags=tags,
            )
        )
    return out


_OS_DETAILS_RE = re.compile(r"^OS details:\s*(.+)$")
_OS_AGGRESSIVE_RE = re.compile(r"^Aggressive OS guesses:\s*(.+)$")
_OS_RUNNING_RE = re.compile(r"^Running:\s*(.+)$")
_OS_NO_MATCH_RE = re.compile(r"^No exact OS matches for host")

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


def parse_shodan_search(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    for match in data.get("matches") or []:
        if not isinstance(match, dict):
            continue
        ip = str(match.get("ip") or "").strip()
        port = match.get("port")
        hostnames = [str(h).lower() for h in (match.get("hostnames") or []) if h]
        if ip:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.HOST,
                    target=target or ip,
                    source_tool="shodan_search",
                    details={
                        "ip": ip,
                        "port": port,
                        "org": match.get("org"),
                        "product": match.get("product"),
                        "hostnames": hostnames[:10],
                        "hostname": hostnames[0] if hostnames else "",
                    },
                    tags=["shodan", "passive"],
                )
            )
        if ip and port is not None:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.PORT,
                    target=target or ip,
                    source_tool="shodan_search",
                    details={
                        "ip": ip,
                        "port": str(port),
                        "protocol": str(match.get("transport") or "tcp"),
                        "product": match.get("product") or "",
                        "banner": (match.get("banner") or "")[:400],
                    },
                    tags=["shodan", "passive", "port"],
                )
            )
        for host in hostnames[:5]:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=target or host,
                    source_tool="shodan_search",
                    details={"hostname": host, "ip": ip},
                    tags=["shodan", "passive"],
                )
            )
    return out


def parse_shodan_host_info(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    ip = str(data.get("ip") or target or "").strip()
    out: list[Observation] = []
    if ip:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target or ip,
                source_tool="shodan_host_info",
                details={
                    "ip": ip,
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "os": data.get("os"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames"),
                },
                tags=["shodan", "passive"],
            )
        )
    os_name = str(data.get("os") or "").strip()
    if os_name and ip:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.BANNER,
                target=target or ip,
                source_tool="shodan_host_info",
                details={"os": os_name},
                tags=["os", "os_detected", "shodan"],
            )
        )
    for port in data.get("ports") or []:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.PORT,
                target=target or ip,
                source_tool="shodan_host_info",
                details={"ip": ip, "port": str(port), "protocol": "tcp"},
                tags=["shodan", "passive", "port"],
            )
        )
    for host in (data.get("hostnames") or [])[:20]:
        host_s = str(host).strip().lower()
        if not host_s:
            continue
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SUBDOMAIN,
                target=target or host_s,
                source_tool="shodan_host_info",
                details={"hostname": host_s, "ip": ip},
                tags=["shodan", "passive"],
            )
        )
    vulns = data.get("vulns") or []
    if vulns:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target or ip,
                source_tool="shodan_host_info",
                details={
                    "kind": "shodan_cve_tags",
                    "title": f"Shodan indexed vulns on {ip}",
                    "description": "Shodan CVE tags are leads — verify before claiming impact",
                    "evidence": ", ".join(str(v) for v in vulns[:30]),
                    "ip": ip,
                    "vuln_count": len(vulns),
                    "cves": [str(v) for v in vulns[:30]],
                    "claimed_severity": "info",
                    "extracted": False,
                },
                tags=["shodan", "cve_lead", "unverified"],
            )
        )
    return out


def parse_subdomain_takeover(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    out: list[Observation] = []
    for row in data.get("vulnerable") or []:
        host = str(row.get("subdomain") or "").strip().lower()
        if not host:
            continue
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target or host,
                source_tool="subdomain_takeover_check",
                details={
                    "kind": "subdomain_takeover",
                    "title": f"Possible subdomain takeover: {host}",
                    "description": str(row.get("reason") or "Fingerprint matched unclaimed SaaS"),
                    "evidence": json.dumps(row, sort_keys=True),
                    "hostname": host,
                    "cname": row.get("cname") or "",
                    "service": row.get("service") or "",
                    "takeover_status": "vulnerable",
                    "claimed_severity": "medium",
                    "extracted": False,
                },
                tags=["takeover", "vulnerable", "cname"],
            )
        )
    for row in data.get("potential") or []:
        host = str(row.get("subdomain") or "").strip().lower()
        if not host:
            continue
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target or host,
                source_tool="subdomain_takeover_check",
                details={
                    "kind": "subdomain_takeover",
                    "title": f"Potential dangling CNAME: {host}",
                    "description": str(row.get("reason") or "SaaS CNAME with empty/404 response"),
                    "evidence": json.dumps(row, sort_keys=True),
                    "hostname": host,
                    "cname": row.get("cname") or "",
                    "service": row.get("service") or "",
                    "takeover_status": "potential",
                    "claimed_severity": "low",
                    "extracted": False,
                },
                tags=["takeover", "potential", "cname"],
            )
        )
    return out


_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_dnsx(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """dnsx -resp lines → host + typed DNS observations (flexible, no CDN hardcoding).

    dnsx prints ``host [TYPE] [VALUE]``; the record type governs the bucket so an
    NS/MX target is never mislabelled as a CNAME (the value shape alone is
    ambiguous — ns1.foo.com and cname.foo.com look identical).
    """
    stdout = _ANSI_RE.sub("", stdout or "")
    _DNS_TYPES = {"A", "AAAA", "CNAME", "NS", "MX", "SOA", "TXT", "PTR", "SRV"}
    host_records: dict[str, dict[str, list[str]]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        host, rest = line.split(" ", 1)
        host = host.strip().lower()
        bucket = host_records.setdefault(
            host, {"ip": [], "cname": [], "ns": [], "mx": []}
        )
        current = "A"  # dnsx may print a bare value with no [TYPE] (plain -a)
        for m in re.finditer(r"\[([^\]]*)\]", rest):
            value = m.group(1).strip()
            if not value:
                continue
            if value.upper() in _DNS_TYPES:
                current = value.upper()
                continue
            if _IP_RE.match(value):
                bucket["ip"].append(value)
            elif value.count(".") >= 1:
                key = {"CNAME": "cname", "NS": "ns", "MX": "mx"}.get(current, "cname")
                bucket[key].append(value.rstrip("."))

    out: list[Observation] = []
    for host, rec in host_records.items():
        for ip in dict.fromkeys(rec["ip"]):
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.HOST,
                    target=target or host,
                    source_tool="dnsx_resolve",
                    details={"hostname": host, "ip": ip, "record_type": "a"},
                    tags=["dns_resolve"],
                )
            )
        for rtype, key in (("CNAME", "cname"), ("NS", "ns"), ("MX", "mx")):
            for value in dict.fromkeys(rec.get(key, [])):
                out.append(
                    Observation(
                        engagement_id=engagement_id,
                        run_id=run_id,
                        type=ObservationType.DNS_RECORD,
                        target=target or host,
                        source_tool="dnsx_resolve",
                        details={"hostname": host, "record_type": rtype.lower(), key: value},
                        tags=[key, "dns_record"],
                    )
                )
    return out


def parse_tlsx(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """tlsx JSON lines → observed TLS / SAN / optional CDN-hint tags."""
    out: list[Observation] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            cert = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(cert.get("host") or target or "")
        ip = str(cert.get("ip") or "")
        sans = cert.get("subject_an") or []
        if isinstance(sans, str):
            sans = [s.strip() for s in sans.split(",") if s.strip()]
        issuer = str(cert.get("issuer_dn") or cert.get("issuer_cn") or "")
        subject = str(cert.get("subject_dn") or cert.get("subject_cn") or "")
        tags: list[str] = ["tls"]
        details = {
            "hostname": host,
            "ip": ip,
            "port": str(cert.get("port") or 443),
            "issuer": issuer[:200],
            "subject": subject[:200],
            "sans": [str(s) for s in sans[:20]],
        }
        blob = f"{issuer} {subject} {' '.join(str(s) for s in sans)}".lower()
        for name, needles in (
            ("cloudflare", ("cloudflare",)),
            ("akamai", ("akamai", "edgekey")),
            ("fastly", ("fastly",)),
            ("cloudfront", ("cloudfront",)),
        ):
            if any(n in blob for n in needles):
                tags.append(f"cdn_hint:{name}")
                details["cdn_hint"] = name
                break
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.CERT,
                target=target or host or ip,
                source_tool="tlsx_inspect",
                details=details,
                tags=tags,
            )
        )
        for san in sans[:30]:
            san_l = str(san).strip().lower().lstrip("*.")
            if san_l and "." in san_l:
                out.append(
                    Observation(
                        engagement_id=engagement_id,
                        run_id=run_id,
                        type=ObservationType.SUBDOMAIN,
                        target=target or host,
                        source_tool="tlsx_inspect",
                        details={"hostname": san_l, "from_san": True},
                        tags=["tls_san"],
                    )
                )
    return out


def parse_crtsh(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """crt.sh JSON → subdomain observations (passive CT)."""
    try:
        certs = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(certs, list):
        return []
    seen: set[str] = set()
    out: list[Observation] = []
    for cert in certs[:500]:
        name_value = str(cert.get("name_value") or "")
        for line in name_value.splitlines():
            domain = line.strip().lower().lstrip("*.")
            if not domain or "." not in domain or domain in seen:
                continue
            seen.add(domain)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=target or domain,
                    source_tool="crt_sh_query",
                    details={"hostname": domain, "source": "crt.sh"},
                    tags=["ct", "passive"],
                )
            )
    return out


def parse_cdn_origin_probe(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Parse dig/curl probe text; also accept JSON if tool parse() was mirrored."""
    out: list[Observation] = []
    # Prefer structured JSON if present in stdout (rare) — else regex sections
    data = None
    stripped = (stdout or "").strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None

    if data is None:
        # Lightweight text parse matching cdn_origin_probe sections
        cdn = None
        edge: list[str] = []
        candidates: list[dict] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            low = line.lower()
            if "cloudflare" in low or "cf-ray" in low or "server: cloudflare" in low:
                cdn = cdn or "cloudflare"
            if "incapsula" in low or "x-iinfo" in low or "x-cdn" in low:
                cdn = cdn or "incapsula"
            if "akamai" in low or "x-akamai" in low:
                cdn = cdn or "akamai"
            if "fastly" in low or "x-fastly" in low:
                cdn = cdn or "fastly"
            if "awselb" in low or "x-amz-cf" in low:
                cdn = cdn or "cloudfront"
            if "tengine" in low or "alibaba" in low:
                cdn = cdn or "alibaba_cdn"
            if line.startswith("A:"):
                edge.extend(x for x in line.split(":", 1)[1].split() if _IP_RE.match(x))
            if "->" in line and ("MX_IP" in line or "SUBDOMAIN_IP" in line):
                ip = line.split("->", 1)[1].strip()
                if _IP_RE.match(ip):
                    candidates.append({"ip": ip, "confidence": 0.4, "signals": ["probe"]})
        data = {
            "cdn_provider": cdn,
            "edge_ips": edge,
            "origin_candidates": candidates,
            "evidence": [],
        }

    provider = data.get("cdn_provider")
    if provider:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=target,
                source_tool="cdn_origin_probe",
                details={
                    "name": f"CDN: {provider}",
                    "cdn_provider": provider,
                    "signal_evidence": [str(x) for x in (data.get("evidence") or [])[:8]],
                },
                tags=["cdn_hint", str(provider)],
            )
        )
    for ip in data.get("edge_ips") or []:
        if not _IP_RE.match(str(ip)):
            continue
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target,
                source_tool="cdn_origin_probe",
                details={"ip": str(ip), "role": "edge"},
                tags=["edge_ip", "cdn_hint"] if provider else ["edge_ip"],
            )
        )
    for cand in data.get("origin_candidates") or []:
        ip = str(cand.get("ip") or "")
        if not _IP_RE.match(ip):
            continue
        conf = float(cand.get("confidence") or 0)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target,
                source_tool="cdn_origin_probe",
                details={
                    "ip": ip,
                    "role": "origin_candidate",
                    "probe_confidence": conf,
                    "signals": [str(s) for s in (cand.get("signals") or [])],
                },
                tags=["origin_candidate"],
            )
        )
    return out


def _unparsed_observation(
    stdout: str,
    *,
    tool_name: str,
    engagement_id: str,
    run_id: str,
    target: str,
) -> list[Observation]:
    """Never silently drop raw output when structured parsing fails or matches nothing."""
    stripped = (stdout or "").strip()
    if not stripped:
        return []
    return [
        Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=ObservationType.RAW,
            target=target,
            source_tool=tool_name,
            details={"snippet": stripped[:2000]},
            tags=[tool_name, "unparsed"],
        )
    ]


def parse_wappalyzer(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return _unparsed_observation(
            stdout, tool_name="wappalyzer_scan", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, dict):
        return []
    technologies = data.get("technologies")
    if not isinstance(technologies, dict):
        return []
    tgt = data.get("target") or target

    out: list[Observation] = []
    for tech_name, info in technologies.items():
        if not isinstance(info, dict):
            continue
        versions = info.get("versions") or []
        version = str(versions[0]) if versions else ""
        cats = [str(c) for c in (info.get("categories") or [])]
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tgt,
                source_tool="wappalyzer_scan",
                details={"name": str(tech_name), "version": version, "categories": cats},
                tags=["wappalyzer"] + [c.lower().replace(" ", "_") for c in cats[:3]],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="wappalyzer_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


_WHATWEB_SKIP_PLUGINS = {"IP", "Country", "UncommonHeaders", "Allow"}


def parse_whatweb(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    text = stdout.strip()
    data: Any = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # WhatWeb sometimes mixes JSON with banner/non-JSON lines — pull the array out.
        json_lines: list[str] = []
        depth = 0
        in_json = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_json = True
            if in_json:
                json_lines.append(line)
                depth += s.count("[") - s.count("]")
                if depth <= 0 and json_lines:
                    break
        if json_lines:
            try:
                data = json.loads("\n".join(json_lines))
            except (json.JSONDecodeError, TypeError):
                data = None
    if data is None:
        return _unparsed_observation(
            stdout, tool_name="whatweb_scan", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, list):
        data = [data]

    out: list[Observation] = []
    seen: set[str] = set()
    for result in data:
        if not isinstance(result, dict):
            continue
        tgt = result.get("target") or target
        plugins = result.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for plugin_name, plugin_data in plugins.items():
            if plugin_name in _WHATWEB_SKIP_PLUGINS or not isinstance(plugin_data, dict):
                continue
            versions = plugin_data.get("version") or []
            version = str(versions[0]) if isinstance(versions, list) and versions else str(versions or "")
            key = f"{plugin_name}:{version}".lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.TECHNOLOGY,
                    target=tgt,
                    source_tool="whatweb_scan",
                    details={"name": str(plugin_name), "version": version, "module": plugin_data.get("module")},
                    tags=["whatweb"],
                )
            )
    return out or _unparsed_observation(
        stdout, tool_name="whatweb_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


def parse_tech_stack(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return _unparsed_observation(
            stdout, tool_name="tech_stack_analyze", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, dict):
        return []
    tgt = data.get("target") or target

    out: list[Observation] = []
    for tech in data.get("unified_stack") or []:
        if not isinstance(tech, dict):
            continue
        name = str(tech.get("name") or "").strip()
        if not name:
            continue
        version = str(tech.get("version") or "")
        cats = [str(c) for c in (tech.get("categories") or [])]
        detected_by = [str(d) for d in (tech.get("detected_by") or [])]
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tgt,
                source_tool="tech_stack_analyze",
                details={
                    "name": name,
                    "version": version,
                    "categories": cats,
                    "detected_by": detected_by,
                },
                tags=["tech_stack"] + [c.lower().replace(" ", "_") for c in cats[:3]],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="tech_stack_analyze", engagement_id=engagement_id, run_id=run_id, target=target
    )


_WAFW00F_DETECTED_RE = re.compile(r"(?i)is behind\s+(.+?)\s+WAF\b")
_WAFW00F_NONE_RE = re.compile(r"(?i)No WAF detected")


def parse_wafw00f(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    text = stdout or ""
    out: list[Observation] = []
    seen: set[str] = set()
    for match in _WAFW00F_DETECTED_RE.finditer(text):
        waf_name = match.group(1).strip()
        key = waf_name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={"waf": waf_name, "raw": match.group(0)[:300]},
                tags=["waf", "wafw00f"],
            )
        )
    if not out and _WAFW00F_NONE_RE.search(text):
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={"waf": None, "detected": False},
                tags=["wafw00f", "no_waf"],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="wafw00f_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


def extract_compact_summary(tool_name: str, stdout: str, *, max_items: int = 12) -> str:
    """Short structured digest of stdout so the LLM sees key facts before truncation."""
    if not stdout.strip():
        return ""

    if tool_name in ("subfinder_scan", "amass_scan", "fierce_scan", "dnsenum_scan"):
        hosts = []
        for line in stdout.splitlines():
            host = line.strip().lower()
            if host and "." in host and " " not in host and not host.startswith("#"):
                hosts.append(host)
        if not hosts:
            return ""
        unique = list(dict.fromkeys(hosts))
        sample = ", ".join(unique[:max_items])
        extra = f" (+{len(unique) - max_items} more)" if len(unique) > max_items else ""
        return f"{len(unique)} subdomain(s): {sample}{extra}"

    if tool_name == "domain_hunter":
        rows = list(_domain_hunter_rows(stdout))
        if not rows:
            return ""
        labels = [
            f"{d} ({conf}{', live' if live else ''})"
            for d, _m, conf, live, *_rest in rows[:max_items]
        ]
        extra = f" (+{len(rows) - max_items} more)" if len(rows) > max_items else ""
        return f"{len(rows)} sister/affiliated domain(s): {', '.join(labels)}{extra}"

    if tool_name == "dnsx_resolve":
        ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", stdout)
        unique = list(dict.fromkeys(ips))
        if unique:
            return f"{len(unique)} IP(s) from dnsx: {', '.join(unique[:max_items])}"
        return ""

    if tool_name == "dnsx_reverse":
        pairs = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or " " not in line:
                continue
            ip = line.split(" ", 1)[0]
            for m in re.finditer(r"\[([^\]]*)\]", line):
                host = m.group(1).strip().rstrip(".").lower()
                if host and host.upper() != "PTR" and "." in host:
                    pairs.append(f"{ip}→{host}")
        unique = list(dict.fromkeys(pairs))
        if not unique:
            return ""
        sample = ", ".join(unique[:max_items])
        extra = f" (+{len(unique) - max_items} more)" if len(unique) > max_items else ""
        return f"{len(unique)} PTR hostname(s): {sample}{extra}"

    if tool_name == "asn_enum":
        if re.search(r"(?im)^route6?:", stdout):
            routes = re.findall(r"(?im)^route6?:\s*(\S+)", stdout)
            unique = list(dict.fromkeys(routes))
            if not unique:
                return ""
            return f"{len(unique)} announced prefix(es): {', '.join(unique[:max_items])}"
        for line in stdout.splitlines():
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 3 and cols[0].isdigit():
                asn = f"AS{cols[0]}"
                name = cols[6] if len(cols) > 6 else (cols[-1] if len(cols) > 3 else "")
                return f"{asn} {name} — prefix {cols[2]}".strip()
        return ""

    if tool_name == "crt_sh_query":
        return f"crt.sh response ~{len(stdout)} chars — see subdomain findings"

    if tool_name == "tlsx_inspect":
        n = sum(1 for ln in stdout.splitlines() if ln.strip().startswith("{"))
        return f"{n} TLS JSON record(s)" if n else ""

    if tool_name in ("cdn_origin_probe", "origin_ip_attribution"):
        return "CDN/origin probe output — check origin_candidate / cdn_hint findings"

    if tool_name == "httpx_probe":
        lines = [ln.strip() for ln in stdout.splitlines() if ln.strip() and not ln.startswith("#")]
        if not lines:
            return ""
        sample = "; ".join(lines[:max_items])
        extra = f" (+{len(lines) - max_items} more)" if len(lines) > max_items else ""
        return f"{len(lines)} live URL(s): {sample}{extra}"

    if tool_name in ("nmap_syn_scan", "nmap_service_scan", "nmap_custom_scan"):
        open_ports: list[str] = []
        host = ""
        for line in stdout.splitlines():
            if line.startswith("Nmap scan report for"):
                host = line.split(" for ", 1)[-1].strip().split()[0]
            match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$", line.strip())
            if match:
                port, proto, state, service = match.groups()
                if state == "open":
                    label = f"{port}/{proto} {service.strip()}"
                    open_ports.append(label)
        if not open_ports:
            return ""
        prefix = f"{host}: " if host else ""
        sample = ", ".join(open_ports[:max_items])
        extra = f" (+{len(open_ports) - max_items} more)" if len(open_ports) > max_items else ""
        return f"{prefix}{len(open_ports)} open port(s): {sample}{extra}"

    if tool_name in ("rustscan_fast_scan", "masscan_high_speed"):
        ports = re.findall(r"(\d+)/tcp\s+open", stdout)
        if not ports:
            return ""
        unique = list(dict.fromkeys(ports))
        sample = ", ".join(unique[:max_items])
        return f"{len(unique)} open port(s): {sample}"

    if tool_name == "naabu_port_scan":
        hits = re.findall(r"(?:([\w.-]+|\d{1,3}(?:\.\d{1,3}){3}):)?(\d{1,5})\b", stdout)
        ports = [p for _h, p in hits if p]
        unique = list(dict.fromkeys(ports))
        if not unique:
            return ""
        return f"{len(unique)} naabu open port(s): {', '.join(unique[:max_items])}"

    if tool_name in ("shodan_search", "shodan_host_info"):
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            return ""
        if tool_name == "shodan_search":
            n = int(data.get("returned") or len(data.get("matches") or []))
            total = data.get("total", n)
            return f"Shodan search returned {n}/{total} match(es)"
        ports = data.get("ports") or []
        return f"Shodan host {data.get('ip', '')}: {len(ports)} port(s)"

    if tool_name == "subdomain_takeover_check":
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            return ""
        summary = data.get("summary") or {}
        return (
            f"takeover check: tested={summary.get('tested', 0)} "
            f"vulnerable={summary.get('vulnerable', 0)} "
            f"potential={summary.get('potential', 0)}"
        )

    if tool_name in ("gau_discovery", "waybackurls_discovery", "hakrawler_crawl"):
        return extract_url_list_digest(tool_name, stdout, max_items=max_items)

    if tool_name == "whois_lookup":
        bits: list[str] = []
        low = stdout.lower()
        for label, pref in (
            ("registrar", "registrar:"),
            ("created", "creation date:"),
            ("expiry", "registry expiry date:"),
            ("dnssec", "dnssec:"),
            ("org", "registrant organization:"),
        ):
            idx = low.find(pref)
            if idx != -1:
                val = stdout[idx + len(pref):].splitlines()[0].strip()
                if val:
                    bits.append(f"{label}={val[:40]}")
        ns = len(re.findall(r"(?im)^\s*name server:", stdout))
        if ns:
            bits.append(f"ns={ns}")
        return ("WHOIS: " + "; ".join(bits)) if bits else ""

    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if len(lines) <= 3:
        return ""
    return f"{len(lines)} output lines; first lines: " + " | ".join(lines[:3])


_URL_LINE_RE = re.compile(r"https?://[^\s\"'<>]+")
# Deliberately excludes bare "?" — most gau/wayback URLs carry a query string,
# so that alone matches almost everything and crowds out genuinely distinctive
# paths/extensions. Path and extension markers stay specific enough to be a
# real signal even across tens of thousands of largely-repetitive URLs.
_INTERESTING_URL_MARKERS = (
    "/api",
    "/admin",
    "/wp-",
    "/graphql",
    "/swagger",
    "/.git",
    "/.env",
    "/config",
    "/backup",
    "/debug",
    "/actuator",
    "/.well-known",
    ".php",
    ".json",
    ".asp",
    ".jsp",
    ".bak",
    ".sql",
    ".zip",
)


# Archive/crawler URL corpora are full of HTML-injection fragments and malformed
# encodings (e.g. http://h/x/%22target=%22_blank, %20onmousedown=, %3cscript%3e).
# Promoting these to URL observations created hundreds of junk graph nodes that
# inflated finalize gap counts and kept tripping the "continue" banner. Reject
# them at the source — they are never real, followable endpoints.
_JUNK_URL_MARKERS = (
    "%22", "%27", "%3c", "%3e", "%20on", "onmouseover", "onmousedown", "onclick",
    "onerror", "onload=", "javascript:", "<", ">", '"', "'", "\\",
)
_HOSTish_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$", re.I)
# A URL path whose FINAL segment is a bare CSS unit value (0.025em, 1199.98px,
# 50%, -0.025em) is never a real endpoint — crawler regexes grab it from CSS
# source text (url(...) tokens, media queries, inline styles).
_CSS_UNIT_SEGMENT_RE = re.compile(
    r"^-?\d+(?:\.\d+)?(?:em|rem|px|vh|vw|vmin|vmax|pt|pc|mm|cm|in|ex|ch|%|deg)$", re.I
)
# A path whose segments are ALL numeric/unit tokens (e.g. grid fractions like
# /1/2, /1/12) is CSS layout source text, not a URL. Date-style paths whose
# FIRST segment is a 4-digit year (/2024/12/25) are common and legit — allowed.
_NUMERIC_SEGMENTS_RE = re.compile(r"^-?\d+(?:\.\d+)?(?:em|rem|px|vh|vw|pt|pc|mm|cm|in|ex|ch|%|deg)?$", re.I)
# A single-segment path that is a JS identifier chain (moment.parseZone,
# moment.utc) with no file extension is property access captured from script
# source, not a URL. Requires the last dot-component to NOT be a common file
# extension so real endpoints (index.php, app.js) are untouched.
_JS_IDENT_CHAIN_RE = re.compile(r"^[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)+$")
_FILE_EXTENSIONS = frozenset(
    "php html htm asp aspx jsp js mjs css json xml txt pdf doc docx xls xlsx ppt pptx "
    "png jpg jpeg gif svg webp ico bmp zip tar gz 7z sql bak env conf ini yaml yml "
    "py go java rb sh md rst log csv tsv map wo ff wasm apk ipa".split()
)


def _is_junk_url(url: str) -> bool:
    low = url.lower()
    if any(m in low for m in _JUNK_URL_MARKERS):
        return True
    try:
        rest = url.split("://", 1)[1]
    except IndexError:
        return True
    host = rest.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0]
    if not host or "." not in host or not _HOSTish_RE.match(host):
        return True
    path = rest.split("/", 1)[1] if "/" in rest else ""
    path = path.split("?", 1)[0].split("#", 1)[0]
    segments = [s for s in path.split("/") if s]
    if segments:
        last = segments[-1]
        if _CSS_UNIT_SEGMENT_RE.match(last):
            return True
        if "." in last and _JS_IDENT_CHAIN_RE.match(last):
            ext = last.rsplit(".", 1)[1].lower()
            if ext not in _FILE_EXTENSIONS:
                return True
        if len(segments) >= 2 and all(_NUMERIC_SEGMENTS_RE.match(s) for s in segments):
            # All-numeric paths are CSS grid fractions (/1/2, /1/12) unless the
            # first segment is a 4-digit year — date paths (/2024/12/25) are real.
            if not re.match(r"^\d{4}$", segments[0]):
                return True
    return False


def _extract_unique_urls(stdout: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for line in stdout.splitlines():
        match = _URL_LINE_RE.search(line)
        if not match:
            continue
        url = match.group(0).rstrip(").,;'\"")
        key = url.lower()
        if key in seen:
            continue
        if _is_junk_url(url):
            continue
        seen.add(key)
        urls.append(url)
    return urls


def extract_url_list_digest(tool_name: str, stdout: str, *, max_items: int = 12) -> str:
    """gau/waybackurls/hakrawler dump raw URL lists with high repetition and low
    per-character signal — surface the security-interesting-looking ones
    (api/admin/config/query-string/etc) instead of an arbitrary first-N sample,
    since those are what the operator actually needs to see without reading
    the full (often 10k+ line) raw dump."""
    urls = _extract_unique_urls(stdout)
    if not urls:
        return ""
    interesting = [u for u in urls if any(m in u.lower() for m in _INTERESTING_URL_MARKERS)]
    sample = interesting[:max_items] or urls[:max_items]
    label = "interesting" if interesting else "sample"
    extra = f" (+{len(urls) - len(sample)} more)" if len(urls) > len(sample) else ""
    return f"{len(urls)} unique URL(s) found — {label}: {', '.join(sample)}{extra}"


def _parse_url_list(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    source_tool: str = "",
    max_findings: int = 300,
) -> list[Observation]:
    """Shared core for gau/waybackurls/hakrawler — one URL per line (sometimes
    with a bracketed prefix). Observations are capped; these tools can return
    tens of thousands of URLs and the digest already carries the full count —
    the rows are for the genuinely followable subset, not a full mirror."""
    urls = _extract_unique_urls(stdout)
    if not urls:
        return _unparsed_observation(
            stdout, tool_name=source_tool, engagement_id=engagement_id, run_id=run_id, target=target
        )

    def _render(url: str) -> Observation:
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        return Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=ObservationType.URL,
            target=host or target,
            source_tool=source_tool,
            details={"url": url[:300], "hostname": host},
            tags=["url_history"],
        )

    return cap_with_accounting(
        urls,
        max_items=max_findings,
        render=_render,
        tool_name=source_tool,
        item_label="URL",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )


def parse_gau(stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = "") -> list[Observation]:
    return _parse_url_list(
        stdout, engagement_id=engagement_id, run_id=run_id, target=target, source_tool="gau_discovery"
    )


def parse_waybackurls(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Observation]:
    return _parse_url_list(
        stdout, engagement_id=engagement_id, run_id=run_id, target=target, source_tool="waybackurls_discovery"
    )


def parse_hakrawler(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Observation]:
    return _parse_url_list(
        stdout, engagement_id=engagement_id, run_id=run_id, target=target, source_tool="hakrawler_crawl"
    )


_WHOIS_FIELDS = {
    "registrar": ("registrar:", "sponsoring registrar:"),
    "registrar_iana_id": ("registrar iana id:", "registrar iana id (iana id):"),
    "registrant_org": ("registrant organization:", "registrant organisation:", "org:", "organization:"),
    "registrant_country": ("registrant country:", "country:"),
    "created": ("creation date:", "created:", "created on:", "domain registration date:", "registered on:"),
    "expiry": ("registry expiry date:", "expiry date:", "expiration date:", "registrar registration expiration date:", "expires:", "expires on:", "domain expiration date:"),
    "updated": ("updated date:", "last updated:", "last modified:", "changed:"),
    "dnssec": ("dnssec:",),
    "abuse_email": ("registrar abuse contact email:", "abuse contact email:"),
    "abuse_phone": ("registrar abuse contact phone:", "abuse contact phone:"),
    "status": ("domain status:", "status:"),
}


def parse_whois(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """WHOIS key:value output → structured registration facts.

    Emits a rich registration observation (registrar / dates / abuse contact),
    an ORGANIZATION observation for the registrant, nameserver observations (so
    the graph can link domain→nameserver), and a dedicated DNSSEC observation
    when unsigned — the exact facts the operator previously had to hand-copy
    out of raw output. Whether "DNSSEC not configured" earns a finding is
    `confidence_for`'s job now, not this parser's.
    """
    text = stdout or ""
    if not text.strip():
        return []
    fields: dict[str, str] = {}
    nameservers: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("%") or line.startswith("#") or line.startswith(">>>"):
            continue
        low = line.lower()
        if low.startswith("name server:") or low.startswith("nserver:") or low.startswith("nameservers:"):
            val = line.split(":", 1)[1].strip().split()[0].rstrip(".").lower() if ":" in line else ""
            if val and "." in val and val not in nameservers:
                nameservers.append(val)
            continue
        for key, prefixes in _WHOIS_FIELDS.items():
            if key in fields:
                continue
            for pref in prefixes:
                if low.startswith(pref):
                    fields[key] = line.split(":", 1)[1].strip()
                    break

    if not fields and not nameservers:
        return []

    apex = (target or "").strip().lower()
    out: list[Observation] = []
    details = {k: v for k, v in fields.items() if v}
    if nameservers:
        details["nameservers"] = nameservers
    if apex:
        details["domain"] = apex

    out.append(
        Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=ObservationType.DNS_RECORD,
            target=apex or target,
            source_tool="whois_lookup",
            details={**details, "kind": "registration"},
            tags=["whois", "registration"],
        )
    )

    org = fields.get("registrant_org")
    if org:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.ORGANIZATION,
                target=apex or target,
                source_tool="whois_lookup",
                details={"organization": org, "domain": apex, "country": fields.get("registrant_country", "")},
                tags=["whois", "organization", "registrant"],
            )
        )

    dnssec = (fields.get("dnssec") or "").lower()
    if dnssec and ("unsigned" in dnssec or "no" == dnssec.strip() or "not" in dnssec):
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.DNS_RECORD,
                target=apex or target,
                source_tool="whois_lookup",
                details={"kind": "dnssec_status", "dnssec": fields.get("dnssec"), "domain": apex, "signed": False},
                tags=["whois", "dnssec", "misconfig"],
            )
        )

    for ns in nameservers[:12]:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.DNS_RECORD,
                target=apex or target,
                source_tool="whois_lookup",
                details={"hostname": apex, "record_type": "ns", "ns": ns, "domain": apex},
                tags=["whois", "ns", "dns_record"],
            )
        )
    return out


# dnsenum prints resource records as "name.  TTL  IN  TYPE  value" across its
# Host/NS/MX/zone-transfer/brute-force sections. One regex covers all of them.
_DNSENUM_RR_RE = re.compile(
    r"^(?P<name>[\w.\-]+?)\.?\s+\d+\s+IN\s+(?P<type>A|AAAA|NS|MX|CNAME|PTR|SOA|TXT)\s+(?P<value>\S+)",
    re.IGNORECASE,
)


def parse_dnsenum(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """dnsenum resource records → subdomain/host/DNS observations.

    Captures the hostnames dnsenum surfaces (zone transfer, brute force, NS/MX)
    that previously fell into the generic unparsed bucket. A records under the
    target become SUBDOMAIN + HOST(ip) observations so the graph builds the
    host→ip edge; NS/MX/CNAME become DNS_RECORD observations.
    """
    apex = (target or "").strip().lower()
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for raw in (stdout or "").splitlines():
        m = _DNSENUM_RR_RE.match(raw.strip())
        if not m:
            continue
        name = m.group("name").strip().lower().rstrip(".")
        rtype = m.group("type").upper()
        value = m.group("value").strip().rstrip(".")
        if not name or "." not in name:
            continue
        key = (name, rtype + ":" + value)
        if key in seen:
            continue
        seen.add(key)

        if rtype in ("A", "AAAA"):
            if apex and (name == apex or name.endswith("." + apex)) and name != apex:
                out.append(
                    Observation(
                        engagement_id=engagement_id,
                        run_id=run_id,
                        type=ObservationType.SUBDOMAIN,
                        target=apex or name,
                        source_tool="dnsenum_scan",
                        details={"hostname": name},
                        tags=["dnsenum", "dns"],
                    )
                )
            if _IP_RE.match(value):
                out.append(
                    Observation(
                        engagement_id=engagement_id,
                        run_id=run_id,
                        type=ObservationType.HOST,
                        target=apex or name,
                        source_tool="dnsenum_scan",
                        details={"hostname": name, "ip": value, "record_type": rtype.lower()},
                        tags=["dnsenum", "dns_resolve"],
                    )
                )
        else:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.DNS_RECORD,
                    target=apex or name,
                    source_tool="dnsenum_scan",
                    details={"hostname": name, "record_type": rtype.lower(), rtype.lower(): value},
                    tags=["dnsenum", rtype.lower(), "dns_record"],
                )
            )
    return out


def _is_ptr_ip_placeholder(host: str, ip: str) -> bool:
    """True when a PTR hostname just re-encodes its own IP — a provider auto-PTR,
    not a real subdomain. Matches the dashed form (``115-186-143-17.example.com``,
    whose leftmost label's digit groups are the IP's octets) and the dotted form
    (``115.186.143.17.example.com``, which begins with the literal IP)."""
    octets = ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return False
    leftmost = host.split(".", 1)[0]
    if re.findall(r"\d+", leftmost) == octets:
        return True
    return host.startswith(ip + ".")


def parse_dnsx_reverse(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """dnsx -ptr lines (``ip [PTR] [hostname]``) → hostname seeds from reverse DNS.

    A PTR that merely re-encodes its own IP (provider auto-PTR such as
    ``115-186-143-17.example.com`` or ``115.186.143.17.example.com``) is NOT a
    real, distinct subdomain — treating it as one inflates the subdomain surface
    and drives a recon-reopen storm against hosts that don't exist. Those are
    recorded as DNS_RECORD evidence (kept, but not surface) while genuine PTR
    hostnames still become SUBDOMAIN seeds."""
    stdout = _ANSI_RE.sub("", stdout or "")
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        ip, rest = line.split(" ", 1)
        ip = ip.strip()
        if not _IP_RE.match(ip):
            continue
        for m in re.finditer(r"\[([^\]]*)\]", rest):
            host = m.group(1).strip().rstrip(".").lower()
            if not host or host.upper() == "PTR" or "." not in host:
                continue
            key = (ip, host)
            if key in seen:
                continue
            seen.add(key)
            placeholder = _is_ptr_ip_placeholder(host, ip)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.DNS_RECORD if placeholder else ObservationType.SUBDOMAIN,
                    target=target or host,
                    source_tool="dnsx_reverse",
                    details={"hostname": host, "ip": ip, "record_type": "ptr"},
                    tags=["reverse_dns", "ptr"] + (["ip_placeholder"] if placeholder else []),
                )
            )
    return out or _unparsed_observation(
        stdout, tool_name="dnsx_reverse", engagement_id=engagement_id, run_id=run_id, target=target
    )


_ASN_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


def parse_asn_enum(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """ASN/netblock output (Team Cymru pipe rows or RADb route objects) → observations.

    Emits an ASN observation plus one observation per announced BGP prefix
    (netblock), each carrying a ``cidr`` in details so downstream steps can
    treat the range as a candidate asset sweep.
    """
    text = stdout or ""
    out: list[Observation] = []

    # RADb route-object format — one prefix per route:/route6: object.
    if re.search(r"(?im)^route6?:", text):
        seen: set[str] = set()
        cur_route = ""
        cur_origin = ""
        cur_descr = ""

        def _emit(route: str, origin: str, descr: str) -> None:
            if not route or route in seen:
                return
            seen.add(route)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.ASN,
                    target=target or route,
                    source_tool="asn_enum",
                    details={"cidr": route, "asn": origin, "role": "netblock", "descr": descr},
                    tags=["netblock", "asn", "asn_prefix"],
                )
            )

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = re.match(r"^(route6?|descr|origin):\s*(.+)$", stripped, re.IGNORECASE)
            if not m:
                continue
            key = m.group(1).lower()
            val = m.group(2).strip()
            if key in ("route", "route6"):
                if cur_route:
                    _emit(cur_route, cur_origin, cur_descr)
                    cur_origin = cur_descr = ""
                cur_route = val
            elif key == "descr" and not cur_descr:
                cur_descr = val
            elif key == "origin":
                cur_origin = val
        _emit(cur_route, cur_origin, cur_descr)
        return out or _unparsed_observation(
            text, tool_name="asn_enum", engagement_id=engagement_id, run_id=run_id, target=target
        )

    # Team Cymru pipe-delimited IP-to-ASN format.
    for line in text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        cols = [c.strip() for c in line.split("|")]
        if cols and cols[0].upper() == "AS":
            continue
        if len(cols) < 3 or not cols[0].isdigit():
            continue
        asn = f"AS{cols[0]}"
        ip = cols[1] if len(cols) > 1 else ""
        prefix = cols[2] if len(cols) > 2 else ""
        country = cols[3] if len(cols) > 3 else ""
        as_name = cols[6] if len(cols) > 6 else (cols[-1] if len(cols) > 3 else "")
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.ASN,
                target=target or ip,
                source_tool="asn_enum",
                details={"asn": asn, "as_name": as_name, "country": country, "ip": ip},
                tags=["asn", "attribution"],
            )
        )
        if _ASN_CIDR_RE.match(prefix):
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.ASN,
                    target=target or prefix,
                    source_tool="asn_enum",
                    details={"cidr": prefix, "asn": asn, "role": "netblock"},
                    tags=["netblock", "asn"],
                )
            )
    return out or _unparsed_observation(
        text, tool_name="asn_enum", engagement_id=engagement_id, run_id=run_id, target=target
    )


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


def _register_recon_network_parsers() -> None:
    from osprey.services.parsers.registry import (
        register_output_digester,
        register_output_parser,
    )

    subdomain_tools = ("subfinder_scan", "amass_scan", "fierce_scan")
    for tool in subdomain_tools:
        register_output_parser(tool, parse_subfinder)
        register_output_digester(tool, lambda stdout, _t=tool: extract_compact_summary(_t, stdout))

    register_output_parser("httpx_probe", parse_httpx)
    register_output_digester("httpx_probe", lambda stdout: extract_compact_summary("httpx_probe", stdout))

    register_output_parser("domain_hunter", parse_domain_hunter)
    register_output_digester("domain_hunter", lambda stdout: extract_compact_summary("domain_hunter", stdout))

    register_output_parser("dnsx_resolve", parse_dnsx)
    register_output_digester("dnsx_resolve", lambda stdout: extract_compact_summary("dnsx_resolve", stdout))
    register_output_parser("dnsx_reverse", parse_dnsx_reverse)
    register_output_digester("dnsx_reverse", lambda stdout: extract_compact_summary("dnsx_reverse", stdout))
    register_output_parser("asn_enum", parse_asn_enum)
    register_output_digester("asn_enum", lambda stdout: extract_compact_summary("asn_enum", stdout))
    register_output_parser("tlsx_inspect", parse_tlsx)
    register_output_digester("tlsx_inspect", lambda stdout: extract_compact_summary("tlsx_inspect", stdout))
    register_output_parser("crt_sh_query", parse_crtsh)
    register_output_digester("crt_sh_query", lambda stdout: extract_compact_summary("crt_sh_query", stdout))
    register_output_parser("cdn_origin_probe", parse_cdn_origin_probe)
    register_output_digester(
        "cdn_origin_probe", lambda stdout: extract_compact_summary("cdn_origin_probe", stdout)
    )
    # cdn_origin_ip / cloudflare_origin_ip removed (duplicate of cdn_origin_probe).
    register_output_parser("origin_ip_attribution", parse_cdn_origin_probe)
    register_output_digester(
        "origin_ip_attribution", lambda stdout: extract_compact_summary("cdn_origin_probe", stdout)
    )

    register_output_parser("shodan_search", parse_shodan_search)
    register_output_digester("shodan_search", lambda stdout: extract_compact_summary("shodan_search", stdout))
    register_output_parser("shodan_host_info", parse_shodan_host_info)
    register_output_digester(
        "shodan_host_info", lambda stdout: extract_compact_summary("shodan_host_info", stdout)
    )
    register_output_parser("subdomain_takeover_check", parse_subdomain_takeover)
    register_output_digester(
        "subdomain_takeover_check",
        lambda stdout: extract_compact_summary("subdomain_takeover_check", stdout),
    )

    nmap_tools = ("nmap_syn_scan", "nmap_service_scan", "nmap_custom_scan")
    for tool in nmap_tools:
        register_output_parser(tool, parse_nmap_text)
        register_output_digester(tool, lambda stdout, _t=tool: extract_compact_summary(_t, stdout))

    # AutoRecon: its tool wrapper folds per-service nmap output into stdout;
    # reuse the nmap parser to extract ports/services from the collected files.
    # (autorecon_comprehensive was a byte-for-byte duplicate of autorecon_scan,
    # removed — resolve_tool_name/_TOOL_ALIASES maps the old name forward.)
    register_output_parser("autorecon_scan", parse_autorecon)

    # masscan is NOT registered here — its console format ("Discovered open
    # port N/tcp on IP") does not match parse_rustscan's regex. It is handled
    # by parsers/network_enum.parse_masscan instead.
    register_output_parser("rustscan_fast_scan", parse_rustscan)
    register_output_digester(
        "rustscan_fast_scan",
        lambda stdout: extract_compact_summary("rustscan_fast_scan", stdout),
    )

    register_output_parser("whois_lookup", parse_whois)
    register_output_digester("whois_lookup", lambda stdout: extract_compact_summary("whois_lookup", stdout))
    register_output_parser("dnsenum_scan", parse_dnsenum)
    register_output_digester("dnsenum_scan", lambda stdout: extract_compact_summary("dnsenum_scan", stdout))

    register_output_parser("naabu_port_scan", parse_naabu)
    register_output_digester("naabu_port_scan", lambda stdout: extract_compact_summary("naabu_port_scan", stdout))

    register_output_parser("wappalyzer_scan", parse_wappalyzer)
    register_output_parser("whatweb_scan", parse_whatweb)
    register_output_parser("tech_stack_analyze", parse_tech_stack)
    register_output_parser("wafw00f_scan", parse_wafw00f)

    register_output_parser("gau_discovery", parse_gau)
    register_output_digester("gau_discovery", lambda stdout: extract_url_list_digest("gau_discovery", stdout))
    register_output_parser("waybackurls_discovery", parse_waybackurls)
    register_output_digester(
        "waybackurls_discovery", lambda stdout: extract_url_list_digest("waybackurls_discovery", stdout)
    )
    register_output_parser("hakrawler_crawl", parse_hakrawler)
    register_output_digester(
        "hakrawler_crawl", lambda stdout: extract_url_list_digest("hakrawler_crawl", stdout)
    )


_register_recon_network_parsers()


async def parse_tool_output(
    tool_name: str,
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Backward-compatible wrapper — delegates to global parser registry."""
    from osprey.services.parsers.registry import parse_tool_output as registry_parse

    return await registry_parse(
        tool_name,
        stdout,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )
