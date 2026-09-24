"""Parsers for the first-class web-recon tools (content / parameter / JS / policy).

All observations are RECON-phase structural facts: discovered paths, hidden
parameters, JS endpoints and secrets, cloud-storage exposure, and email/policy
posture. Parameters and endpoints are additionally tagged
``injection_point_candidate`` so the eventual vuln phase inherits a
ready-made attack-surface list instead of re-deriving it from raw URL dumps
(the "attack-surface handoff" seed).

Nothing here claims impact it did not observe — a content hit is a fact that
an HTTP response was seen at that status; whether a hardcoded secret is valid,
or a weak SPF policy is worth reporting, is `confidence_for`'s job (Plan 03),
never this module's.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers._capping import cap_with_accounting

_INTERESTING_PATH = (
    "/api", "/v1", "/v2", "/graphql", "/admin", "/auth", "/login", "/token",
    "/oauth", "/upload", "/internal", "/private", "/debug", "/actuator",
    "/swagger", "/openapi", "/.env", "/.git", "/config", "/backup", "/console",
)


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def _is_interesting(url: str) -> bool:
    low = url.lower()
    return any(m in low for m in _INTERESTING_PATH)


def _content_hit(
    url: str,
    status: str,
    size: str,
    *,
    source_tool: str,
    engagement_id: str,
    run_id: str,
    target: str,
) -> Observation:
    interesting = _is_interesting(url)
    tags = ["content-discovery", source_tool]
    if interesting:
        tags.append("interesting_path")
    if status in ("401", "403"):
        tags.append("access_controlled")
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.URL,
        target=url,
        source_tool=source_tool,
        details={
            "hostname": _host_of(url),
            "url": url,
            "status": status,
            "size": size,
            "interesting": interesting,
        },
        tags=tags,
    )


# ---------------------------------------------------------------------------
# feroxbuster --json (NDJSON: {"type":"response","url":..,"status":..,"content_length":..})
# ---------------------------------------------------------------------------
def parse_feroxbuster(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") != "response":
            continue
        url = str(rec.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(
            url, str(rec.get("status") or ""), str(rec.get("content_length") or ""),
            source_tool="feroxbuster_scan", engagement_id=engagement_id, run_id=run_id, target=target,
        ))
    return out or _dir_text_fallback(stdout, "feroxbuster_scan", engagement_id, run_id, target)


# ---------------------------------------------------------------------------
# ffuf -json (NDJSON: {"url":..,"status":..,"length":..,"input":{"FUZZ":..}})
# ---------------------------------------------------------------------------
def parse_ffuf(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        # ffuf NDJSON per-result records carry url+status; skip the config header.
        if "status" not in rec:
            continue
        url = str(rec.get("url") or "").strip()
        fuzz = ""
        if isinstance(rec.get("input"), dict):
            fuzz = str(rec["input"].get("FUZZ") or "")
        if not url and fuzz and target:
            url = f"{target.rstrip('/')}/{fuzz}"
        if not url or url in seen:
            continue
        seen.add(url)
        obs = _content_hit(
            url, str(rec.get("status") or ""), str(rec.get("length") or ""),
            source_tool="ffuf_scan", engagement_id=engagement_id, run_id=run_id, target=target,
        )
        if fuzz:
            obs.details["fuzz"] = fuzz
        out.append(obs)
    return out or _dir_text_fallback(stdout, "ffuf_scan", engagement_id, run_id, target)


# ---------------------------------------------------------------------------
# gobuster dir text: "/admin (Status: 200) [Size: 1234]"
# gobuster dns text (v3.8): "host.example.com 1.2.3.4,2600:9000:..."
# (older builds print "Found: host.example.com" — both accepted)
# ---------------------------------------------------------------------------
_GOBUSTER_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d{3})\)(?:\s*\[Size:\s*(\d+)\])?")
_GOBUSTER_DNS_RE = re.compile(r"^Found:\s*\[?([^\s\]]+)\]?$", re.IGNORECASE)
_GOBUSTER_DNS_IP_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)\s+([0-9a-fA-F.:,]+)$"
)


def parse_gobuster(stdout, *, engagement_id="", run_id="", target=""):
    base = (target or "").rstrip("/")
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        m_dns = _GOBUSTER_DNS_RE.match(line)
        m_dns_ip = _GOBUSTER_DNS_IP_RE.match(line) if not m_dns else None
        if m_dns or m_dns_ip:
            host = (m_dns.group(1) if m_dns else m_dns_ip.group(1)).strip().lower().rstrip(".")
            ips = [ip for ip in (m_dns_ip.group(2).split(",") if m_dns_ip else []) if ip]
            if not host or "." not in host or host in seen:
                continue
            seen.add(host)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=target or host,
                    source_tool="gobuster_scan",
                    details={"hostname": host, "source": "dns-bruteforce", "ips": ips},
                    tags=["dns", "active", "subdomain-enum"],
                )
            )
            continue
        m = _GOBUSTER_RE.match(line)
        if not m:
            continue
        path, status, size = m.group(1), m.group(2), m.group(3) or ""
        url = path if path.startswith("http") else f"{base}{path if path.startswith('/') else '/' + path}"
        if url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(
            url, status, size, source_tool="gobuster_scan",
            engagement_id=engagement_id, run_id=run_id, target=target,
        ))
    return out


def _dir_text_fallback(stdout, source_tool, engagement_id, run_id, target):
    """Fallback for feroxbuster/ffuf default (non-JSON) text output."""
    base = (target or "").rstrip("/")
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        # feroxbuster text: "200      GET  ...  http://t/x" ; ffuf text: "x  [Status: 200, Size: 5]"
        m_ferox = re.match(r"^(\d{3})\s+\w+\s+.*?(https?://\S+)", line)
        m_ffuf = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
        if m_ferox:
            status, url = m_ferox.group(1), m_ferox.group(2)
            size = ""
        elif m_ffuf and base:
            url = f"{base}/{m_ffuf.group(1)}"
            status, size = m_ffuf.group(2), m_ffuf.group(3)
        else:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(url, status, size, source_tool=source_tool,
                                engagement_id=engagement_id, run_id=run_id, target=target))
    return out


# ---------------------------------------------------------------------------
# Parameter discovery — arjun text + passive extraction from URL corpora
# ---------------------------------------------------------------------------
_ARJUN_FOUND_RE = re.compile(r"(?i)parameters?\s+found\s*[:>-]*\s*(.+)$")


def _param_observation(param, url, *, source_tool, engagement_id, run_id, target):
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.INJECTION_POINT,
        target=url or target,
        source_tool=source_tool,
        details={"parameter": param, "url": url, "hostname": _host_of(url)},
        tags=["parameter", "injection_point_candidate", source_tool],
    )


def parse_arjun(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        m = _ARJUN_FOUND_RE.search(line.strip())
        if not m:
            continue
        for param in re.split(r"[,\s]+", m.group(1).strip()):
            param = param.strip().strip("'\"[]")
            if not param or not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,40}$", param) or param in seen:
                continue
            seen.add(param)
            out.append(_param_observation(
                param, target, source_tool="arjun_scan",
                engagement_id=engagement_id, run_id=run_id, target=target,
            ))
    return out


_X8_FOUND_RE = re.compile(r"(?i)(?:found|discovered|reflects?|new)\b.*?[:\-]?\s*([A-Za-z0-9_.\-\[\]]{1,40})\s*$")
_X8_PARAM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,40}$")


def parse_x8(stdout, *, engagement_id="", run_id="", target=""):
    """x8 active param brute output → injection-point candidate observations.

    x8's terminal output varies by version; it flags each discovered parameter,
    often as a bare token or after a 'found'/'reflects' marker. We accept both a
    JSON list of params and line tokens, and reuse the shared param observation.
    """
    out: list[Observation] = []
    seen: set[str] = set()
    text = (stdout or "").strip()

    def _emit(param: str) -> None:
        param = param.strip().strip("'\"[](),")
        if not param or param in seen or not _X8_PARAM_TOKEN_RE.match(param):
            return
        # Drop obvious non-params (status words, http verbs).
        if param.lower() in {"get", "post", "put", "delete", "found", "new", "reflects", "none", "true", "false"}:
            return
        seen.add(param)
        out.append(_param_observation(
            param, target, source_tool="x8_parameter_discovery",
            engagement_id=engagement_id, run_id=run_id, target=target,
        ))

    # JSON form: {"params": [...]} or a bare list.
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
            items = data.get("params") if isinstance(data, dict) else data
            for it in items or []:
                _emit(str(it if not isinstance(it, dict) else it.get("name", "")))
            if out:
                return out
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass

    for line in text.splitlines():
        line = line.strip()
        # x8 marks found params with a leading indicator or lists them plainly.
        m = _X8_FOUND_RE.search(line)
        if m:
            _emit(m.group(1))
    return out


def extract_parameters_from_urls(urls, *, source_tool, engagement_id, run_id, target, max_params=120):
    """Passive param mining: pull unique parameter names out of a URL corpus
    (gau / wayback / katana output). Cheap replacement for the flaky paramspider
    CLI — the archive URLs we already collect ARE the parameter source."""
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
        except ValueError:
            continue
        host = _host_of(url)
        for param in qs:
            key = (host, param)
            if key in seen or not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,40}$", param):
                continue
            seen.add(key)
            out.append(_param_observation(
                param, url, source_tool=source_tool,
                engagement_id=engagement_id, run_id=run_id, target=target,
            ))
            if len(out) >= max_params:
                return out
    return out


# ---------------------------------------------------------------------------
# katana -jsonl : {"timestamp":..,"request":{"endpoint":"http://.."},"response":{"status_code":..}}
# ---------------------------------------------------------------------------
def parse_katana(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    urls: list[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = rec.get("request") or {}
            url = str(req.get("endpoint") or rec.get("endpoint") or "").strip()
        elif line.startswith("http"):
            url = line.split()[0]
        else:
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=url, source_tool="katana_crawl",
            details={"hostname": _host_of(url), "url": url},
            tags=["crawl", "katana"] + (["interesting_path"] if _is_interesting(url) else []),
        ))
    # Attack-surface handoff: also mine parameters from the crawled URLs.
    out.extend(extract_parameters_from_urls(
        urls, source_tool="katana_crawl", engagement_id=engagement_id, run_id=run_id, target=target))
    return out


# ---------------------------------------------------------------------------
# js_recon JSON — endpoints, secrets, cloud assets
# ---------------------------------------------------------------------------
def parse_js_recon(stdout, *, engagement_id="", run_id="", target=""):
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    tgt = data.get("target") or target

    all_endpoints = [str(ep) for ep in (data.get("endpoints") or [])]
    out.extend(cap_with_accounting(
        all_endpoints,
        max_items=400,
        render=lambda ep: Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.JS_ENDPOINT,
            target=tgt, source_tool="js_recon",
            details={"endpoint": ep, "hostname": _host_of(ep) or _host_of(tgt)},
            tags=["js-endpoint"] + (["interesting_path", "injection_point_candidate"]
                                    if _is_interesting(ep) else []),
        ),
        tool_name="js_recon",
        item_label="JS endpoint",
        engagement_id=engagement_id, run_id=run_id, target=tgt,
    ))

    for sec in (data.get("secrets") or []):
        stype = str(sec.get("type") or "secret")
        high = bool(sec.get("high_signal"))
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SECRET,
            target=tgt, source_tool="js_recon",
            details={
                "secret_type": stype,
                "match": sec.get("match"),
                "source": sec.get("source"),
                "high_signal": high,
            },
            tags=["secret", "js-secret", stype] + (["verify_validity"] if high else []),
        ))

    for c in (data.get("cloud_assets") or []):
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.ENDPOINT,
            target=tgt, source_tool="js_recon",
            details={
                "kind": "cloud_storage_reference",
                "cloud_type": c.get("type"),
                "bucket": c.get("bucket"),
                "match": c.get("match"),
            },
            tags=["cloud-asset", str(c.get("type"))],
        ))
    return out


# ---------------------------------------------------------------------------
# email_security_probe — sectioned text (=== MX/SPF/DMARC/DKIM ===)
# ---------------------------------------------------------------------------
def parse_email_security(stdout, *, engagement_id="", run_id="", target=""):
    section = ""
    mx: list[str] = []
    spf = ""
    dmarc = ""
    dkim: list[str] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if line.startswith("=== ") and line.endswith(" ==="):
            section = line.strip("= ").lower()
            continue
        if not line:
            continue
        if section == "mx" and line != "NONE":
            mx.append(line)
        elif section == "spf":
            spf = "" if line == "NONE" else line
        elif section == "dmarc":
            dmarc = "" if line == "NONE" else line
        elif section == "dkim" and line.startswith("DKIM_SELECTOR:"):
            dkim.append(line.split(":", 1)[1].strip())

    out: list[Observation] = []
    dom = (target or "").strip().lower()
    details = {
        "domain": dom, "mx_count": len(mx),
        "has_spf": bool(spf), "has_dmarc": bool(dmarc), "dkim_selectors": dkim,
        "spf": spf[:200], "dmarc": dmarc[:200],
    }
    out.append(Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=ObservationType.DNS_RECORD,
        target=dom, source_tool="email_security_probe",
        details=details,
        tags=["email-security", "dns"],
    ))
    # Spoofing-exposure facts: missing OR weak SPF/DMARC policy is structural,
    # reportable data — the earned-finding pipeline decides if it's worth a
    # finding, this parser only states what it observed.
    weaknesses: list[str] = []
    if not spf:
        weaknesses.append("no SPF record")
    elif re.search(r"[~?]all", spf):
        qual = "~all (softfail)" if "~all" in spf else "?all (neutral)"
        weaknesses.append(f"SPF {qual} — does not hard-fail spoofed senders")
    if not dmarc:
        weaknesses.append("no DMARC record")
    else:
        pol = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)", dmarc)
        policy = (pol.group(1).lower() if pol else "none")
        details["dmarc_policy"] = policy
        if policy == "none":
            weaknesses.append("DMARC p=none — monitoring only, does not block spoofed mail")
    if weaknesses:
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.DNS_RECORD,
            target=dom, source_tool="email_security_probe",
            details={**details, "weaknesses": weaknesses},
            tags=["email-security", "spoofing", "misconfig"],
        ))
    return out


# ---------------------------------------------------------------------------
# well_known_probe — sectioned text (=== PATH /x === / STATUS: nnn / body)
# ---------------------------------------------------------------------------
def parse_well_known(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    base = (target or "").strip()
    cur_path = ""
    cur_status = ""
    body_lines: list[str] = []

    def _flush():
        if not cur_path or cur_status != "200":
            return
        url = cur_path if cur_path.startswith("http") else f"{base.rstrip('/')}{cur_path}"
        body = "\n".join(body_lines)
        tags = ["well-known", "policy-file"]
        details = {
            "path": cur_path, "url": url, "status": cur_status,
            "hostname": _host_of(url), "body_snippet": body[:300],
        }
        # robots.txt Disallow entries are attack-surface leads.
        disallow = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)
        if disallow:
            details["disallow"] = disallow[:40]
            tags.append("robots_disallow")
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=url, source_tool="well_known_probe",
            details=details, tags=tags,
        ))
        # Emit the disallowed paths themselves as URL leads.
        for d in disallow[:30]:
            if not d or d == "/":
                continue
            durl = f"{base.rstrip('/')}{d}" if d.startswith("/") else d
            out.append(Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.URL,
                target=durl, source_tool="well_known_probe",
                details={"url": durl, "from": "robots_disallow"},
                tags=["robots_disallow"] + (["interesting_path"] if _is_interesting(durl) else []),
            ))

    for raw in (stdout or "").splitlines():
        line = raw.rstrip()
        pm = re.match(r"^=== PATH (\S+) ===$", line.strip())
        if pm:
            _flush()
            cur_path, cur_status, body_lines = pm.group(1), "", []
            continue
        if line.strip().startswith("STATUS:"):
            cur_status = line.split(":", 1)[1].strip()
            continue
        if line.strip() == "=== DONE ===":
            _flush()
            cur_path = ""
            continue
        if cur_path:
            body_lines.append(line)
    _flush()
    return out


# ---------------------------------------------------------------------------
# Tech-stack fingerprinting (tech_stack_analyze) and WAF identification
# (wafw00f_scan) — both print human-readable text; neither had a backend
# parser, so their observations always fell through to the raw "Output from …"
# placeholder. TECHNOLOGY observations here feed the tree's tech_by_host and
# the engine's tech-conditional dispatch (e.g. WordPress -> wpscan).
# ---------------------------------------------------------------------------
def parse_tech_stack(stdout, *, engagement_id="", run_id="", target=""):
    """tech_stack_analyze prints one JSON line per probe and a final line
    carrying unified_stack (the merged, deduped technology list). The last
    valid line wins — earlier probe lines are per-method detail."""
    out: list[Observation] = []
    data = None
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            cand = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(cand, dict) and cand.get("unified_stack"):
            data = cand
    if not data:
        return out

    stack = data.get("unified_stack") or []
    seen: set[str] = set()
    for tech in stack:
        if not isinstance(tech, dict):
            continue
        name = str(tech.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        version = str(tech.get("version") or "").strip()
        tool_confidence = str(tech.get("confidence") or "low")
        tech_target = target or str(tech.get("target") or "").strip()
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tech_target,
                source_tool="tech_stack_analyze",
                details={
                    "hostname": tech_target,
                    "name": name,
                    "version": version,
                    "categories": tech.get("categories", []),
                    "detected_by": tech.get("detected_by"),
                    "tool_reported_confidence": tool_confidence,
                },
                tags=["technology", "fingerprint"],
            )
        )
    return out


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Note the \s+ before WAF, not \b: WAF names can end in ')' ('Cloudfront
# (Amazon)') and \b does not bind after a non-word char. The generic
# suspicion line ('behind a WAF or some kind of proxy') is filtered by the
# placeholder-name guard in the parser.
_WAF_BEHIND_RE = re.compile(
    r"\b(is|may be|seems to be)\s+(?:behind|protected by)\s+"
    r"([A-Za-z0-9][A-Za-z0-9 /_\-()]{1,80}?)\s+WAF\b",
    re.IGNORECASE,
)

_WAF_PLACEHOLDER_NAMES = frozenset({"a", "an", "some", "any", "the"})


def parse_wafw00f(stdout, *, engagement_id="", run_id="", target=""):
    """wafw00f verdicts: 'The site <url> is behind <Name> WAF.' / '…may be
    behind…' / '…protected by…'. Real output carries ANSI color codes on the
    same line and WAF names can contain parentheses ('Cloudfront (Amazon)'),
    so strip escapes first and allow those characters. A run that detected
    nothing prints no WAF line — legitimately empty, not a raw placeholder
    (parse_tool_output suppresses the fallback for verdict tools)."""
    out: list[Observation] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = _ANSI_RE.sub("", raw_line)
        m = _WAF_BEHIND_RE.search(line)
        if not m:
            continue
        name = " ".join(m.group(2).split())
        if not name or name.lower() in _WAF_PLACEHOLDER_NAMES or name.lower() in seen:
            continue
        seen.add(name.lower())
        verdict = m.group(1).lower()
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={
                    "hostname": target,
                    "waf": name,
                    "verdict": verdict,
                    "raw_line": line.strip()[:500],
                },
                tags=["waf", "technology"],
            )
        )
    return out


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------
def _content_digest(tool):
    def _d(stdout: str) -> str:
        n = sum(1 for ln in (stdout or "").splitlines()
                if ln.strip().startswith("{") or re.search(r"\(Status:|\[Status:", ln))
        return f"{tool}: ~{n} hit(s)" if n else ""
    return _d


def _js_digest(stdout: str) -> str:
    try:
        d = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return ""
    return (
        f"js_recon: {d.get('js_file_count', 0)} JS file(s), "
        f"{d.get('endpoint_count', 0)} endpoint(s), "
        f"{len(d.get('secrets') or [])} secret(s), "
        f"{len(d.get('cloud_assets') or [])} cloud ref(s)"
    )


def _register() -> None:
    from osprey.services.parsers.registry import (
        register_output_digester,
        register_output_parser,
    )

    register_output_parser("feroxbuster_scan", parse_feroxbuster)
    register_output_digester("feroxbuster_scan", _content_digest("feroxbuster"))
    register_output_parser("ffuf_scan", parse_ffuf)
    register_output_digester("ffuf_scan", _content_digest("ffuf"))
    register_output_parser("gobuster_scan", parse_gobuster)
    register_output_digester("gobuster_scan", _content_digest("gobuster"))
    register_output_parser("arjun_scan", parse_arjun)
    register_output_parser("arjun_parameter_discovery", parse_arjun)
    register_output_parser("x8_parameter_discovery", parse_x8)
    register_output_parser("katana_crawl", parse_katana)
    register_output_parser("js_recon", parse_js_recon)
    register_output_digester("js_recon", _js_digest)
    register_output_parser("email_security_probe", parse_email_security)
    register_output_parser("well_known_probe", parse_well_known)
    register_output_parser("tech_stack_analyze", parse_tech_stack)
    register_output_parser("wafw00f_scan", parse_wafw00f)


_register()
