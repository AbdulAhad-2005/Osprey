"""Deterministic stdout parsers for passive-OSINT tools.

Each parser turns a tool's stdout into typed identity findings (EMAIL / USERNAME /
PERSON / PHONE / SOCIAL_ACCOUNT / DOCUMENT). Relationship hints go in ``metadata``
(person / domain / username / network) so the engagement graph can build the
name → email → account pivot edges. All OSINT findings are leads: person / social
matches default to UNVERIFIED, structural leads to INFERRED (see finding.py).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from osprey.schemas.finding import (
    EvidenceGrade,
    Finding,
    FindingConfidence,
    FindingType,
)
from osprey.services.parsers.email_extract import (
    EMAIL_RE as _EMAIL_RE,
    email_domain,
    emails_from_json_value,
    extract_emails,
    extract_harvest_json,
    is_valid_email,
    matches_target_domain,
    normalize_email,
    strip_ansi,
)
from osprey.services.parsers.registry import register_many

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# A "phone number" needs at least 7 digits and no letters; strip separators.
_PHONE_RE = re.compile(r"^[0-9+\-().\s/]{7,20}$")

_SOCIAL_HOSTS = {
    "twitter.com": "twitter",
    "x.com": "twitter",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "github.com": "github",
    "youtube.com": "youtube",
    "t.me": "telegram",
    "tiktok.com": "tiktok",
    "medium.com": "medium",
    "reddit.com": "reddit",
}


def _valid_email(candidate: str) -> bool:
    """True only for a real-looking contact address — no placeholders, no
    Cloudflare obfuscation, no template domains."""
    return is_valid_email(candidate)


def _email_finding(
    addr: str,
    *,
    tool: str,
    desc: str,
    engagement_id: str,
    run_id: str,
    target: str,
    source: str,
    extra_meta: dict | None = None,
) -> Finding:
    normalized = normalize_email(addr)
    host = email_domain(normalized)
    meta = {
        "source": source,
        "email_domain": host,
        "matches_target_domain": matches_target_domain(normalized, target),
    }
    if extra_meta:
        meta.update(extra_meta)
    return _mk(
        FindingType.EMAIL,
        normalized,
        tool=tool,
        desc=desc,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
        metadata=meta,
    )


def _valid_phone(candidate: str) -> bool:
    candidate = (candidate or "").strip()
    if not candidate or not _PHONE_RE.fullmatch(candidate):
        return False
    digits = re.sub(r"\D", "", candidate)
    return 7 <= len(digits) <= 15


def _network_of(url: str) -> str:
    try:
        host = (urlparse(url).netloc or "").lower().lstrip("www.")
    except ValueError:
        return ""
    for key, net in _SOCIAL_HOSTS.items():
        if key in host:
            return net
    return host.split(":")[0]


def _mk(
    ftype: FindingType,
    title: str,
    *,
    tool: str,
    desc: str,
    engagement_id: str,
    run_id: str,
    target: str,
    metadata: dict | None = None,
    tags: list[str] | None = None,
    grade: EvidenceGrade | None = None,
    confidence: FindingConfidence = FindingConfidence.LIKELY,
) -> Finding:
    kwargs: dict = dict(
        engagement_id=engagement_id,
        run_id=run_id,
        phase="osint",
        finding_type=ftype,
        title=title[:200],
        description=desc,
        evidence=title[:400],
        confidence=confidence,
        source_tool=tool,
        target=target,
        metadata=metadata or {},
        tags=(tags or []) + ["osint"],
    )
    if grade is not None:
        kwargs["evidence_grade"] = grade
    return Finding(**kwargs)


# ---------------------------------------------------------------------------

def parse_web_contact_harvest(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    data = extract_harvest_json(stdout)
    if data is None:
        # Last-chance: emails still sitting in a truncated / non-JSON dump.
        recovered = extract_emails(stdout)
        if not recovered:
            return []
        tgt = target or ""
        return [
            _email_finding(
                addr, tool="web_contact_harvest",
                desc=f"Email published on {tgt or 'target site'}",
                engagement_id=engagement_id, run_id=run_id, target=tgt,
                source="website", extra_meta={"partial": True},
            )
            for addr in recovered
        ]
    if not isinstance(data, dict):
        return []

    domain = str(data.get("domain") or target or "")
    tgt = target or domain
    out: list[Finding] = []
    seen_email: set[str] = set()

    # WAF/CDN block → record it so an empty crawl isn't mistaken for "no contacts".
    if data.get("blocked"):
        out.append(_mk(
            FindingType.OBSERVATION,
            f"web_contact_harvest blocked (HTTP {data.get('seed_status')}) on {domain}",
            tool="web_contact_harvest",
            desc="Site behind WAF/CDN — passive crawl incomplete; use theharvester/crt.sh/gau",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata={"seed_status": data.get("seed_status")}, tags=["waf_blocked"],
        ))

    emails = emails_from_json_value(data.get("emails", []))
    if not emails:
        # Truncated snapshot or emails only present as raw text beside JSON.
        emails = extract_emails(stdout)
    for email in emails:
        if email in seen_email:
            continue
        seen_email.add(email)
        out.append(_email_finding(
            email, tool="web_contact_harvest",
            desc=f"Email published on {domain or 'target site'}",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            source="website",
        ))
    for phone in data.get("phones", []):
        phone = str(phone).strip()
        if not _valid_phone(phone):
            continue
        out.append(_mk(
            FindingType.PHONE, phone, tool="web_contact_harvest",
            desc=f"Phone published on {domain or 'target site'}",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata={"source": "website"},
        ))
    for name in data.get("names", []):
        out.append(_mk(
            FindingType.PERSON, str(name), tool="web_contact_harvest",
            desc=f"Person named on {domain or 'target site'}",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata={"organization": domain} if domain else {},
        ))
    for sa in data.get("social", []):
        if not isinstance(sa, dict):
            continue
        url = str(sa.get("url") or "")
        if not url:
            continue
        uname = str(sa.get("username") or "")
        net = str(sa.get("network") or _network_of(url))
        meta = {"network": net}
        if uname:
            meta["username"] = uname
        out.append(_mk(
            FindingType.SOCIAL_ACCOUNT, url, tool="web_contact_harvest",
            desc=f"{net} account linked from {domain or 'target site'}",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata=meta, tags=[net] if net else [],
        ))
        if uname:
            out.append(_mk(
                FindingType.USERNAME, uname, tool="web_contact_harvest",
                desc=f"Handle used on {net}",
                engagement_id=engagement_id, run_id=run_id, target=tgt,
                metadata={"network": net},
            ))
    # Structured empty crawl: do not fall through to LLM/raw-output padding.
    if not any(f.finding_type == FindingType.EMAIL for f in out) and not data.get("blocked"):
        out.append(_mk(
            FindingType.OBSERVATION,
            f"No public emails found on {domain or tgt or 'target'}",
            tool="web_contact_harvest",
            desc="Harvest JSON parsed; no valid contact addresses after normalization",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata={"emails": 0, "pages_crawled": data.get("pages_crawled")},
            tags=["empty_result"],
        ))
    return out


def _theharvester_section(low: str) -> str | None:
    """Map a theHarvester banner line to a result section. Ignore person names."""
    compact = low.lstrip("[-*+] ").strip()
    if compact.startswith("no emails") or "emails found" in compact:
        return "emails"
    if compact.startswith("no hosts") or "hosts found" in compact:
        return "hosts"
    if compact.startswith("no ips") or compact.startswith("ips found") or "ips found" in compact:
        return "ips"
    if "people found" in compact or ("linkedin" in compact and "found" in compact):
        return "people"
    return None


def parse_theharvester(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    out: list[Finding] = []
    seen_email: set[str] = set()
    seen_host: set[str] = set()
    section = ""
    tgt = target or ""
    text = strip_ansi(stdout or "")
    saw_email_section = False

    payload = extract_harvest_json(text)
    json_emails: list[str] = []
    if isinstance(payload, dict) and "emails" in payload:
        json_emails = emails_from_json_value(payload.get("emails"))
        for host in payload.get("hosts") or payload.get("host") or []:
            host_s = str(host).split(":")[0].strip().lower()
            if host_s and "." in host_s and " " not in host_s and host_s not in seen_host:
                seen_host.add(host_s)
                out.append(_mk(
                    FindingType.SUBDOMAIN, host_s, tool="theharvester",
                    desc=f"Host harvested for {tgt or 'target'}",
                    engagement_id=engagement_id, run_id=run_id, target=tgt,
                    metadata={"hostname": host_s},
                ))
        for nm in payload.get("people") or payload.get("interesting_people") or []:
            name = str(nm).strip()
            if 3 <= len(name) <= 60 and _EMAIL_RE.search(name) is None:
                out.append(_mk(
                    FindingType.PERSON, name, tool="theharvester",
                    desc="Person harvested from public sources (e.g. LinkedIn)",
                    engagement_id=engagement_id, run_id=run_id, target=tgt,
                    metadata={"organization": tgt} if tgt else {},
                ))

    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        header = _theharvester_section(low)
        if header is not None:
            section = header
            if section == "emails":
                saw_email_section = True
            continue
        if not line or line.startswith("["):
            continue

        if section == "hosts" and _EMAIL_RE.search(line) is None:
            host = line.split(":")[0].strip().lower()
            if host and "." in host and " " not in host and host not in seen_host:
                seen_host.add(host)
                out.append(_mk(
                    FindingType.SUBDOMAIN, host, tool="theharvester",
                    desc=f"Host harvested for {tgt or 'target'}",
                    engagement_id=engagement_id, run_id=run_id, target=tgt,
                    metadata={"hostname": host},
                ))
        elif section == "people":
            nm = line.strip()
            if 3 <= len(nm) <= 60 and _EMAIL_RE.search(nm) is None:
                out.append(_mk(
                    FindingType.PERSON, nm, tool="theharvester",
                    desc="Person harvested from public sources (e.g. LinkedIn)",
                    engagement_id=engagement_id, run_id=run_id, target=tgt,
                    metadata={"organization": tgt} if tgt else {},
                ))

    # Whole-blob extract so partial/timeout dumps and emails outside the
    # labelled section still become EMAIL findings.
    for addr in json_emails + extract_emails(text):
        if addr in seen_email:
            continue
        seen_email.add(addr)
        out.append(_email_finding(
            addr, tool="theharvester",
            desc="Email harvested from public sources",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            source="search_engine",
        ))

    if saw_email_section and not seen_email:
        out.append(_mk(
            FindingType.OBSERVATION,
            f"No emails found by theharvester for {tgt or 'target'}",
            tool="theharvester",
            desc="theHarvester reported an email section; no valid addresses after normalization",
            engagement_id=engagement_id, run_id=run_id, target=tgt,
            metadata={"emails": 0},
            tags=["empty_result"],
        ))
    return out


def _parse_username_sites(
    stdout: str, tool: str, *, engagement_id: str, run_id: str, target: str
) -> list[Finding]:
    """Shared parser for sherlock / maigret style '[+] Site: url' output."""
    out: list[Finding] = []
    uname = target.strip()
    seen: set[str] = set()
    if uname:
        out.append(_mk(
            FindingType.USERNAME, uname, tool=tool,
            desc="Username searched across social/web sites",
            engagement_id=engagement_id, run_id=run_id, target=uname,
        ))
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if "http" not in line:
            continue
        m = _URL_RE.search(line)
        if not m:
            continue
        url = m.group(0).rstrip(".,);")
        if url in seen:
            continue
        seen.add(url)
        net = _network_of(url)
        meta = {"network": net}
        if uname:
            meta["username"] = uname
        out.append(_mk(
            FindingType.SOCIAL_ACCOUNT, url, tool=tool,
            desc=f"Account found on {net} for username '{uname}'",
            engagement_id=engagement_id, run_id=run_id, target=uname,
            metadata=meta, tags=[net] if net else [],
        ))
    return out


def parse_sherlock(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    return _parse_username_sites(
        stdout, "sherlock", engagement_id=engagement_id, run_id=run_id, target=target
    )


def parse_maigret(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    return _parse_username_sites(
        stdout, "maigret", engagement_id=engagement_id, run_id=run_id, target=target
    )


def parse_social_analyzer(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return _parse_username_sites(
            stdout, "social_analyzer", engagement_id=engagement_id, run_id=run_id, target=target
        )
    detected = data.get("detected", []) if isinstance(data, dict) else []
    uname = target.strip()
    out: list[Finding] = []
    for item in detected:
        if not isinstance(item, dict):
            continue
        url = str(item.get("link") or item.get("url") or "")
        if not url:
            continue
        net = str(item.get("site") or _network_of(url))
        meta = {"network": net}
        if uname:
            meta["username"] = uname
        out.append(_mk(
            FindingType.SOCIAL_ACCOUNT, url, tool="social_analyzer",
            desc=f"Detected {net} profile for '{uname}'",
            engagement_id=engagement_id, run_id=run_id, target=uname,
            metadata=meta, tags=[net] if net else [],
        ))
    return out


def parse_holehe(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    email = target.strip().lower()
    out: list[Finding] = []
    if email and _EMAIL_RE.fullmatch(email):
        out.append(_mk(
            FindingType.EMAIL, email, tool="holehe",
            desc="Email checked for account existence",
            engagement_id=engagement_id, run_id=run_id, target=email,
            metadata={"source": "holehe"},
        ))
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("[+]"):
            continue
        site = line[3:].strip().split()[0] if len(line) > 3 else ""
        if site:
            out.append(_mk(
                FindingType.OBSERVATION, f"{email} registered at {site}", tool="holehe",
                desc="Account exists for this email (existence only, no credentials)",
                engagement_id=engagement_id, run_id=run_id, target=email,
                metadata={"email": email, "service": site}, tags=["email-account", site],
            ))
    return out


def parse_phoneinfoga(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    phone = target.strip()
    out: list[Finding] = []
    if phone:
        out.append(_mk(
            FindingType.PHONE, phone, tool="phoneinfoga",
            desc="Phone number profiled (country/carrier/footprint)",
            engagement_id=engagement_id, run_id=run_id, target=phone,
            metadata={"source": "phoneinfoga"},
        ))
    for raw in (stdout or "").splitlines():
        low = raw.strip().lower()
        if any(k in low for k in ("carrier:", "country:", "line type:", "local:")):
            out.append(_mk(
                FindingType.OBSERVATION, raw.strip()[:160], tool="phoneinfoga",
                desc="Phone footprint detail",
                engagement_id=engagement_id, run_id=run_id, target=phone,
                metadata={"phone": phone}, tags=["phone"],
            ))
    return out


def parse_dnstwist(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    out: list[Finding] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        perm = str(row.get("domain") or row.get("domain-name") or "").strip().lower()
        if not perm or perm == (target or "").lower():
            continue
        if not (row.get("dns_a") or row.get("dns-a") or row.get("dns_ns") or row.get("dns-ns")):
            continue
        out.append(_mk(
            FindingType.OBSERVATION, f"Look-alike domain: {perm}", tool="dnstwist",
            desc=f"Registered typosquat / look-alike of {target}",
            engagement_id=engagement_id, run_id=run_id, target=target,
            metadata={"lookalike_domain": perm, "fuzzer": str(row.get("fuzzer", ""))},
            tags=["typosquat", "brand-abuse"],
        ))
    return out


def parse_metagoofil(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for raw in (stdout or "").splitlines():
        for m in _URL_RE.findall(raw):
            url = m.rstrip(".,);")
            if url in seen:
                continue
            if not url.lower().rsplit(".", 1)[-1][:4] in (
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "csv"
            ):
                continue
            seen.add(url)
            out.append(_mk(
                FindingType.DOCUMENT, url, tool="metagoofil",
                desc="Public document indexed for the target domain",
                engagement_id=engagement_id, run_id=run_id, target=target,
                metadata={"domain": target}, tags=["document"],
            ))
    return out


def parse_email_permute(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    name = str(data.get("name") or "")
    mx = bool(data.get("mx"))
    out: list[Finding] = []
    for cand in data.get("candidates", []):
        addr = str(cand)
        if not _valid_email(addr):
            continue
        out.append(_mk(
            FindingType.EMAIL, normalize_email(addr), tool="email_permute",
            desc=f"Candidate email for '{name}' (format guess — unconfirmed)",
            engagement_id=engagement_id, run_id=run_id, target=target,
            metadata={"person": name, "mx": mx},
            tags=["candidate"], grade=EvidenceGrade.UNVERIFIED,
            confidence=FindingConfidence.HYPOTHESIS,
        ))
    return out


# exiftool default output: "Tag Name<padding>: Value". Person-bearing tags feed
# PERSON leads; software/GPS are observations. Closes the document→author pivot
# (metagoofil → exiftool_extract) that the OSINT methodology skill describes.
# "author"/"last modified by"/"artist" are reliably people. "creator" is
# ambiguous (a person in Office docs, but the producing application in PDFs), so
# it is person-typed only when the value does not look like software.
_EXIF_PERSON_TAGS = {"author", "last modified by", "artist", "owner name", "by-line", "contact"}
_EXIF_MAYBE_PERSON_TAGS = {"creator"}
_EXIF_INFO_TAGS = {
    "software", "creator tool", "producer", "company", "application",
    "gps position", "gps latitude", "gps longitude", "create date",
    "modify date", "manufacturer", "camera model name",
}
_EXIF_SOFTWARE_HINT = re.compile(
    r"(?i)\b(word|excel|powerpoint|office|acrobat|distiller|photoshop|indesign|"
    r"libreoffice|openoffice|pdf|latex|ghostscript|canon|nikon|iphone|android|"
    r"chrome|firefox|adobe|microsoft|apple|google|v?\d+\.\d+)\b"
)
_EXIF_LINE_RE = re.compile(r"^([A-Za-z0-9 /\-]+?)\s*:\s*(.+)$")


def parse_exiftool(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    out: list[Finding] = []
    seen_people: set[str] = set()
    for raw in (stdout or "").splitlines():
        m = _EXIF_LINE_RE.match(raw.strip())
        if not m:
            continue
        tag = m.group(1).strip().lower()
        value = m.group(2).strip()
        if not value or value.lower() in ("", "n/a", "unknown"):
            continue
        is_person_tag = tag in _EXIF_PERSON_TAGS or (
            tag in _EXIF_MAYBE_PERSON_TAGS and not _EXIF_SOFTWARE_HINT.search(value)
        )
        if is_person_tag:
            name = value.strip()
            key = name.lower()
            if key in seen_people or len(name) > 80:
                continue
            seen_people.add(key)
            out.append(_mk(
                FindingType.PERSON, name, tool="exiftool_extract",
                desc=f"Person from document metadata ({tag})",
                engagement_id=engagement_id, run_id=run_id, target=target,
                metadata={"person": name, "source": "document_metadata", "exif_tag": tag},
                tags=["document-metadata", "person-lead"],
                grade=EvidenceGrade.INFERRED,
            ))
        elif tag in _EXIF_INFO_TAGS or tag in _EXIF_MAYBE_PERSON_TAGS:
            out.append(_mk(
                FindingType.OBSERVATION, f"{tag}: {value}"[:120], tool="exiftool_extract",
                desc=f"Document metadata ({tag})",
                engagement_id=engagement_id, run_id=run_id, target=target,
                metadata={"exif_tag": tag, "value": value[:200]},
                tags=["document-metadata", tag.replace(" ", "_")],
                grade=EvidenceGrade.OBSERVED,
            ))
    return out


def _register_osint_parsers() -> None:
    register_many(["web_contact_harvest"], parser=parse_web_contact_harvest)
    register_many(["theharvester"], parser=parse_theharvester)
    register_many(["sherlock"], parser=parse_sherlock)
    register_many(["maigret"], parser=parse_maigret)
    register_many(["social_analyzer"], parser=parse_social_analyzer)
    register_many(["holehe"], parser=parse_holehe)
    register_many(["phoneinfoga"], parser=parse_phoneinfoga)
    register_many(["dnstwist"], parser=parse_dnstwist)
    register_many(["metagoofil"], parser=parse_metagoofil)
    register_many(["email_permute"], parser=parse_email_permute)
    register_many(["exiftool_extract"], parser=parse_exiftool)


_register_osint_parsers()
