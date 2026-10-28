"""Historical/crawled URL-list parsers (gau/wayback/hakrawler)."""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers._capping import cap_with_accounting
from osprey.services.parsers.recon_network._shared import _unparsed_observation
from osprey.services.parsers.recon_network._shared import _CSS_UNIT_SEGMENT_RE, _FILE_EXTENSIONS, _HOSTish_RE, _INTERESTING_URL_MARKERS, _JS_IDENT_CHAIN_RE, _JUNK_URL_MARKERS, _NUMERIC_SEGMENTS_RE, _URL_LINE_RE


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

    out = cap_with_accounting(
        urls,
        max_items=max_findings,
        render=_render,
        tool_name=source_tool,
        item_label="URL",
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )
    # Attack-surface handoff (plan 19): these archived URLs are the dominant
    # real-world source of already-parameterized requests (gau/waybackurls
    # routinely surface thousands, e.g. "article.php?id=5") — mine them the
    # same way parse_katana already does for its own crawl, or the mandatory
    # SQLi coverage this feeds (tech_dispatch's injection_point_candidates
    # rule) never fires for gau/waybackurls/hakrawler at all, only katana.
    from osprey.services.parsers.web_recon import extract_parameters_from_urls

    out.extend(extract_parameters_from_urls(
        urls, source_tool=source_tool, engagement_id=engagement_id, run_id=run_id, target=target,
    ))
    return out


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


