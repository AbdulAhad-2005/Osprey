"""Best-effort parse of freeform script/shell probe output into structured findings.

Scripts invent their own print formats. We extract common lines so chat evidence
becomes durable memory — without requiring a named tool parser.

Explicit markers (print from platform_script):
  FINDING|observed|high|url|Title|evidence
  PATH /api/x 401
  REL|host:a|same_app_as|host:b|shared cookie
  REL|inferred|host:a|likely_origin_of|ip:1.2.3.4|evidence
  HYPOTHESIS|erp shares auth with ess|same Set-Cookie domain
"""

from __future__ import annotations

import re

from osprey.schemas.finding import (
    EvidenceGrade,
    Finding,
    FindingConfidence,
    FindingType,
)
from osprey.services.parsers._capping import cap_with_accounting

# https://host/...  200  Title here
_URL_STATUS_RE = re.compile(
    r"(?P<url>https?://[^\s\|,;]+)\s+"
    r"(?P<status>\d{3})\b"
    r"(?:\s+[|/\-]\s*|\s+)?"
    r"(?P<title>[^\n]{0,120})?",
    re.IGNORECASE,
)

# host:443 open / 209.1.2.3:3389/tcp open
_HOST_PORT_RE = re.compile(
    r"\b(?P<host>(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}|"
    r"\d{1,3}(?:\.\d{1,3}){3})"
    r":(?P<port>\d{1,5})"
    r"(?:/(?P<proto>tcp|udp))?"
    r"\s+(?P<state>open|filtered|closed)\b",
    re.IGNORECASE,
)

# Simple "host -> 1.2.3.4" or "host resolves to 1.2.3.4"
_RESOLVE_RE = re.compile(
    r"\b(?P<host>(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})"
    r"\s*(?:->|resolves?\s+to|=)\s*"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)

_MAX_FINDINGS = 200

# When a probe line's "title" is actually an error-page body fragment, the URL
# is NOT an asset — it is an error response being echoed (Cloudflare 403 page,
# nginx 404 page, SPA fallback HTML, "access denied", etc.). Skip those lines
# so error bodies don't ingest as discovered URLs.
_ERROR_BODY_MARKERS = re.compile(
    r"access denied|error code \d{3,4}|error 10\d\d|request unsuccessful|"
    r"error page|bad request|not found|the requested (url|resource)|"
    r"404 not found|403 forbidden|502 bad gateway|503 service unavailable|"
    r"504 gateway|cloudflare|cf-ray|attention required|enable javascript|"
    r"enable cookies|verify you are human|please turn javascript|"
    r"<\s*(html|body|div|script)\b|DOCTYPE|half-open|gid=error|"
    r"challenge-platform|ray\.id|error\.cf",
    re.IGNORECASE,
)
_ERROR_STATUSES = {"400", "401", "403", "404", "405", "429", "500", "502", "503", "504"}

# Explicit script→memory contract (print these lines from platform_script):
# FINDING|observed|high|url|Open admin API|/api/admin 200 {"users":...}
_FINDING_MARKER_RE = re.compile(
    r"(?im)^FINDING\|(?P<grade>observed|inferred|unverified)"
    r"\|(?P<sev>none|info|low|medium|high|critical)"
    r"\|(?P<ftype>url|host|port|service|technology|observation|subdomain"
    r"|email|username|person|phone|social_account|organization|document)"
    r"\|(?P<title>[^|\n]{1,160})"
    r"\|(?P<evidence>[^\n]{0,800})\s*$"
)

# PATH /api/v1/users 401  or  ENDPOINT https://x/api 200
_PATH_LINE_RE = re.compile(
    r"(?im)^(?:PATH|ENDPOINT|ROUTE)\s+"
    r"(?P<path>(?:https?://\S+|/[^\s]{1,200}))"
    r"(?:\s+(?P<status>\d{3}))?"
    r"(?:\s+(?P<extra>[^\n]{0,120}))?"
)

# REL|host:a.example|same_app_as|host:b.example|shared JS hash
# Optional leading grade: REL|inferred|host:a|same_app_as|host:b|evidence
_REL_MARKER_RE = re.compile(
    r"(?im)^REL\|"
    r"(?:(?P<grade>observed|inferred|unverified)\|)?"
    r"(?P<source>[^|\n]{1,200})"
    r"\|(?P<relation>[^|\n]{1,64})"
    r"\|(?P<target>[^|\n]{1,200})"
    r"\|(?P<evidence>[^\n]{0,800})\s*$"
)

# HYPOTHESIS|short claim|evidence snippet
_HYPOTHESIS_MARKER_RE = re.compile(
    r"(?im)^HYPOTHESIS\|"
    r"(?P<title>[^|\n]{1,160})"
    r"\|(?P<evidence>[^\n]{0,800})\s*$"
)


def extract_rel_markers(stdout: str) -> list[dict[str, str]]:
    """Parse REL| lines for operator_memory.apply_script_rel_markers."""
    out: list[dict[str, str]] = []
    if not (stdout or "").strip():
        return out
    for match in _REL_MARKER_RE.finditer(stdout):
        out.append(
            {
                "grade": (match.group("grade") or "inferred").strip().lower(),
                "source": match.group("source").strip(),
                "relation": match.group("relation").strip(),
                "target": match.group("target").strip(),
                "evidence": (match.group("evidence") or "").strip()
                or "REL marker from script",
            }
        )
    return out


def parse_freeform_probe_output(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    source_tool: str = "script",
) -> list[Finding]:
    """Extract URL/port/host facts from messy script stdout."""
    if not (stdout or "").strip():
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for match in _HYPOTHESIS_MARKER_RE.finditer(stdout):
        title = match.group("title").strip()
        key = f"hyp:{title}:{match.group('evidence')[:40]}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="",
                finding_type=FindingType.OBSERVATION,
                title=f"HYPOTHESIS: {title}",
                description="Explicit HYPOTHESIS marker from script/shell",
                evidence=(match.group("evidence") or "")[:800],
                confidence=FindingConfidence.HYPOTHESIS,
                evidence_grade=EvidenceGrade.UNVERIFIED,
                source_tool=source_tool,
                target=target,
                raw_data=(match.group("evidence") or "")[:800],
                tags=["script_marker", "hypothesis", "grade:unverified"],
            )
        )
    for match in _FINDING_MARKER_RE.finditer(stdout):
        title = match.group("title").strip()
        key = f"marker:{title}:{match.group('evidence')[:40]}"
        if key in seen:
            continue
        seen.add(key)
        try:
            ftype = FindingType(match.group("ftype"))
        except ValueError:
            ftype = FindingType.OBSERVATION
        try:
            grade = EvidenceGrade(match.group("grade"))
        except ValueError:
            grade = EvidenceGrade.INFERRED
        from osprey.schemas.finding import ClaimSeverity, clamp_claim_severity

        try:
            sev = ClaimSeverity(match.group("sev"))
        except ValueError:
            sev = ClaimSeverity.INFO
        sev = clamp_claim_severity(grade, sev)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="",
                finding_type=ftype,
                title=title,
                description="Explicit FINDING marker from script/shell",
                evidence=(match.group("evidence") or "")[:800],
                confidence=FindingConfidence.CONFIRMED
                if grade == EvidenceGrade.OBSERVED
                else FindingConfidence.LIKELY,
                evidence_grade=grade,
                claim_severity=sev,
                source_tool=source_tool,
                target=target,
                raw_data=(match.group("evidence") or "")[:800],
                tags=["script_marker", f"grade:{grade.value}"],
            )
        )

    for match in _PATH_LINE_RE.finditer(stdout):
        path = match.group("path").rstrip(".,;)]}>\"'")
        status = match.group("status") or ""
        extra = (match.group("extra") or "").strip()
        key = f"path:{path}:{status}"
        if key in seen:
            continue
        seen.add(key)
        url = path if path.startswith("http") else path
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="recon",
                finding_type=FindingType.URL if path.startswith("http") or path.startswith("/") else FindingType.OBSERVATION,
                title=f"{url}" + (f" [{status}]" if status else ""),
                description=extra[:120] or "Path/endpoint from script",
                evidence=match.group(0)[:500],
                confidence=FindingConfidence.CONFIRMED,
                evidence_grade=EvidenceGrade.OBSERVED if status else EvidenceGrade.INFERRED,
                source_tool=source_tool,
                target=target or url,
                metadata={"path": path, "status_code": status},
                tags=["script_parsed", "path_probe"],
            )
        )

    for match in _URL_STATUS_RE.finditer(stdout):
        url = match.group("url").rstrip(".,;)]}>\"'")
        status = match.group("status")
        title = (match.group("title") or "").strip().strip("|/- ")
        # Error-body guard: 4xx/5xx lines whose "title" is error-page boilerplate
        # are bodies being echoed, not discovered assets.
        if status in _ERROR_STATUSES and _ERROR_BODY_MARKERS.search(title):
            continue
        key = f"url:{url}:{status}"
        if key in seen:
            continue
        seen.add(key)
        host = ""
        try:
            parts = url.split("//", 1)
            raw_host = parts[-1] if len(parts) > 1 else parts[0]
            host = raw_host.split("/", 1)[0].split(":", 1)[0].lower()
        except Exception:
            host = ""
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="recon",
                finding_type=FindingType.URL,
                title=url,
                description=f"HTTP {status}" + (f" — {title[:80]}" if title else ""),
                evidence=match.group(0)[:500],
                confidence=FindingConfidence.CONFIRMED,
                evidence_grade=EvidenceGrade.OBSERVED,
                source_tool=source_tool,
                target=target or url,
                metadata={
                    "hostname": host,
                    "status_code": status,
                    "http_title": title[:120],
                },
                tags=["script_parsed", "observed_http"],
            )
        )

    for match in _HOST_PORT_RE.finditer(stdout):
        host = match.group("host").lower()
        port = match.group("port")
        proto = (match.group("proto") or "tcp").lower()
        state = match.group("state").lower()
        if state != "open":
            continue
        key = f"port:{host}:{port}/{proto}"
        if key in seen:
            continue
        seen.add(key)
        meta: dict = {"port": port, "protocol": proto, "hostname": host}
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            meta["ip"] = host
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="network",
                finding_type=FindingType.PORT,
                title=f"{host}:{port}/{proto} open",
                description="Open port from script/shell output",
                evidence=match.group(0)[:300],
                confidence=FindingConfidence.CONFIRMED,
                evidence_grade=EvidenceGrade.INFERRED,
                source_tool=source_tool,
                target=target or host,
                metadata=meta,
                tags=["script_parsed"],
            )
        )

    for match in _RESOLVE_RE.finditer(stdout):
        host = match.group("host").lower()
        ip = match.group("ip")
        key = f"host:{host}:{ip}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                phase="recon",
                finding_type=FindingType.HOST,
                title=host,
                description=f"Resolves to {ip}",
                evidence=match.group(0)[:300],
                confidence=FindingConfidence.CONFIRMED,
                evidence_grade=EvidenceGrade.INFERRED,
                source_tool=source_tool,
                target=target or host,
                metadata={"hostname": host, "ip": ip},
                tags=["script_parsed", "dns_resolve"],
            )
        )

    if len(findings) <= _MAX_FINDINGS:
        return findings
    return cap_with_accounting(
        findings,
        max_items=_MAX_FINDINGS,
        render=lambda f: f,
        tool_name=source_tool,
        item_label="finding",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )
