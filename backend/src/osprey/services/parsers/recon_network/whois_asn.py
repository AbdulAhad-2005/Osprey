"""WHOIS, dnsenum, reverse-DNS and ASN parsers."""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers.recon_network._shared import _unparsed_observation
from osprey.services.parsers.recon_network.dns_infra import _ANSI_RE, _IP_RE
from osprey.services.parsers.recon_network.urls import _WHOIS_FIELDS


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


