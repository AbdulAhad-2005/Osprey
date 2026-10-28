"""DNS, cert, takeover and CDN/origin infra parsers."""

from __future__ import annotations

import json
import re

from osprey.schemas.observation import Observation, ObservationType


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


