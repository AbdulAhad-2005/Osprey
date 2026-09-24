"""Best-effort parse of freeform script/shell probe output into structural Observations.

Scripts invent their own print formats. We extract common lines so chat evidence
becomes durable memory — without requiring a named tool parser.

Explicit markers (print from platform_script):
  FINDING|confirmed|high|url|Title|evidence
  PATH /api/x 401
  REL|host:a|same_app_as|host:b|shared cookie
  REL|likely|host:a|likely_origin_of|ip:1.2.3.4|evidence
  HYPOTHESIS|erp shares auth with ess|same Set-Cookie domain

A ``FINDING|...`` marker is a script *claiming* a verdict — per Plan 03's one
law, say-so is not evidence. It becomes a SCANNER_SIGNAL observation carrying
the claim as structural detail (``claimed_confidence``/``claimed_severity``/
``claimed_finding_type``); ``platform_file_finding``/``promote_observations``
decide, from whatever evidence actually backs it, whether it earns a real
Finding.
"""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation, ObservationType
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

_MAX_OBSERVATIONS = 200

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
# FINDING|confirmed|high|url|Open admin API|/api/admin 200 {"users":...}
_FINDING_MARKER_RE = re.compile(
    r"(?im)^FINDING\|(?P<confidence>confirmed|likely|hypothesis)"
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
# Optional leading confidence: REL|likely|host:a|same_app_as|host:b|evidence
_REL_MARKER_RE = re.compile(
    r"(?im)^REL\|"
    r"(?:(?P<confidence>confirmed|likely|hypothesis)\|)?"
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
                "confidence": (match.group("confidence") or "likely").strip().lower(),
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
) -> list[Observation]:
    """Extract URL/port/host facts from messy script stdout."""
    if not (stdout or "").strip():
        return []

    out: list[Observation] = []
    seen: set[str] = set()

    for match in _HYPOTHESIS_MARKER_RE.finditer(stdout):
        title = match.group("title").strip()
        key = f"hyp:{title}:{match.group('evidence')[:40]}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target, source_tool=source_tool,
                details={
                    "kind": "hypothesis_marker",
                    "claim": title,
                    "evidence": (match.group("evidence") or "")[:800],
                },
                tags=["script_marker", "hypothesis"],
            )
        )
    for match in _FINDING_MARKER_RE.finditer(stdout):
        title = match.group("title").strip()
        key = f"marker:{title}:{match.group('evidence')[:40]}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target, source_tool=source_tool,
                details={
                    "kind": "finding_marker",
                    "claimed_finding_type": match.group("ftype"),
                    "claimed_confidence": match.group("confidence"),
                    "claimed_severity": match.group("sev"),
                    "title": title,
                    "evidence": (match.group("evidence") or "")[:800],
                },
                tags=["script_marker"],
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
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.URL if path.startswith("http") or path.startswith("/") else ObservationType.RAW,
                target=target or url, source_tool=source_tool,
                details={
                    "path": path,
                    "status_code": status,
                    "extra": extra[:120],
                    "raw": match.group(0)[:500],
                },
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
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.URL,
                target=target or url, source_tool=source_tool,
                details={
                    "url": url,
                    "hostname": host,
                    "status_code": status,
                    "http_title": title[:120],
                    "raw": match.group(0)[:500],
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
        details: dict = {"port": port, "protocol": proto, "hostname": host}
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            details["ip"] = host
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.PORT,
                target=target or host, source_tool=source_tool,
                details=details,
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
        out.append(
            Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.HOST,
                target=target or host, source_tool=source_tool,
                details={"hostname": host, "ip": ip},
                tags=["script_parsed", "dns_resolve"],
            )
        )

    if len(out) <= _MAX_OBSERVATIONS:
        return out
    return cap_with_accounting(
        out,
        max_items=_MAX_OBSERVATIONS,
        render=lambda o: o,
        tool_name=source_tool,
        item_label="observation",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )
