"""Compact human-readable digests of tool stdout."""

from __future__ import annotations

import json
import re

from osprey.services.parsers.recon_network.subdomains import _domain_hunter_rows
from osprey.services.parsers.recon_network.urls import extract_url_list_digest


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


# Deliberately excludes bare "?" — most gau/wayback URLs carry a query string,
# so that alone matches almost everything and crowds out genuinely distinctive
# paths/extensions. Path and extension markers stay specific enough to be a
# real signal even across tens of thousands of largely-repetitive URLs.


# Archive/crawler URL corpora are full of HTML-injection fragments and malformed
# encodings (e.g. http://h/x/%22target=%22_blank, %20onmousedown=, %3cscript%3e).
# Promoting these to URL observations created hundreds of junk graph nodes that
# inflated finalize gap counts and kept tripping the "continue" banner. Reject
# them at the source — they are never real, followable endpoints.
# A URL path whose FINAL segment is a bare CSS unit value (0.025em, 1199.98px,
# 50%, -0.025em) is never a real endpoint — crawler regexes grab it from CSS
# source text (url(...) tokens, media queries, inline styles).
# A path whose segments are ALL numeric/unit tokens (e.g. grid fractions like
# /1/2, /1/12) is CSS layout source text, not a URL. Date-style paths whose
# FIRST segment is a 4-digit year (/2024/12/25) are common and legit — allowed.
# A single-segment path that is a JS identifier chain (moment.parseZone,
# moment.utc) with no file extension is property access captured from script
# source, not a URL. Requires the last dot-component to NOT be a common file
# extension so real endpoints (index.php, app.js) are untouched.


