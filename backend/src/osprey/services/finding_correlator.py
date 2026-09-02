"""Cross-finding correlator — READ-ONLY hypothesis *suggestions* from memory.

This module NEVER writes to the engagement graph. It inspects existing findings
and returns candidate relationships (same IP + similar title, shared cookie
domain, URL fan-out) using the patterns in ``config/correlation_rules.yaml`` as
matching logic. The driving LLM decides whether any candidate is worth
committing — and only then calls ``platform_graph_link`` / ``platform_tag_asset``.

Why read-only: a background writer that auto-minted ``evidence_grade=inferred``
edges into the same graph real evidence lives in made "confirmed vs speculative"
a flag every reader had to remember to check, and on shared hosting / CDN blocks
it linked genuinely unrelated hosts. Suggestions the LLM chose to record stay
first-class (``platform_think`` / ``platform_graph_link``); guesses a schedule
generated unasked do not. Config: config/correlation_rules.yaml.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any

from osprey.services.config_loader import read_config

logger = logging.getLogger(__name__)

_COOKIE_DOMAIN = re.compile(r"(?i)(?:^|[;\s])Domain=([^;\s]+)")
_TITLE_FROM_FINDING = re.compile(r"(?i)(?:title:\s*|\[\d{3}\]\s+)(.+)$")
_HOST_FROM_URL = re.compile(r"(?i)^https?://([^/:]+)")

_READ_ONLY_NOTE = (
    "Read-only suggestions — these are hypotheses, not graph edges. Confirm the "
    "ones worth keeping with platform_graph_link / platform_tag_asset (and only "
    "claim CRITICAL with observed evidence)."
)


@lru_cache(maxsize=1)
def _load_rules() -> list[dict[str, Any]]:
    data = read_config("correlation_rules.yaml", "correlation_rules.json")
    return list(data.get("correlations") or [])


def reload_correlation_rules() -> None:
    _load_rules.cache_clear()


def find_correlations(
    engagement_id: str,
    *,
    seed_target: str = "",
) -> dict[str, Any]:
    """Return candidate cross-finding correlations for an engagement. Read-only.

    Never writes to the graph. The returned ``candidates`` are suggestions the
    LLM may choose to commit via platform_graph_link / platform_tag_asset.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return {"candidates": [], "count": 0}

    rules = _load_rules()
    if not rules:
        return {"candidates": [], "count": 0, "note": "no correlation rules"}

    from osprey.services.findings_store import get_findings_store
    from osprey.services.engagement_graph import get_engagement_graph

    findings = get_findings_store().list(engagement_id=eid, run_id=None, limit=2000)
    graph = get_engagement_graph()
    candidates: list[dict[str, Any]] = []

    for rule in rules:
        rtype = (rule.get("type") or "").strip()
        try:
            if rtype == "same_ip_similar_title":
                candidates.extend(_corr_same_ip_titles(eid, findings, graph, rule))
            elif rtype == "shared_cookie_domain":
                candidates.extend(_corr_shared_cookie(findings, rule))
            elif rtype == "host_url_fanout":
                candidates.extend(_corr_url_fanout(findings, rule))
        except Exception as exc:  # noqa: BLE001
            logger.warning("correlation %s failed: %s", rule.get("id"), exc)

    return {
        "engagement_id": eid,
        "seed_target": seed_target or "",
        "candidates": candidates,
        "count": len(candidates),
        "note": _READ_ONLY_NOTE,
    }


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def _title_overlap(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / float(max(len(ta), len(tb)))


def _extract_http_title(f: Any) -> str | None:
    tags = {str(t).lower() for t in (f.tags or [])}
    title = (f.title or "").strip()
    if "http_title" in tags:
        m = _TITLE_FROM_FINDING.search(title)
        return (m.group(1) if m else title).strip()[:120] or None
    if title.lower().startswith("http ") and "title:" in title.lower():
        m = _TITLE_FROM_FINDING.search(title)
        return (m.group(1) if m else None)
    return None


def _host_for_finding(f: Any) -> str | None:
    target = (getattr(f, "target", None) or "").strip()
    if target:
        if "://" in target:
            m = _HOST_FROM_URL.match(target)
            return m.group(1).lower() if m else None
        if "." in target and " " not in target and not target.startswith("/"):
            return target.lower().split(":")[0]
    title = (f.title or "").strip()
    m = _HOST_FROM_URL.match(title)
    if m:
        return m.group(1).lower()
    ft = str(getattr(f.finding_type, "value", f.finding_type) or "")
    if ft in ("subdomain", "host") and "." in title and " " not in title:
        return title.lower().split()[0]
    return None


def _corr_same_ip_titles(
    eid: str,
    findings: list,
    graph: Any,
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    min_overlap = float(rule.get("min_title_token_overlap") or 0.5)
    min_len = int(rule.get("min_title_len") or 4)
    max_links = int(rule.get("max_links_per_run") or 12)
    relation = str(rule.get("relation") or "likely_same_app")
    grade = str(rule.get("evidence_grade") or "inferred")
    # Shared-infra guard: hosts on a heavily-shared IP (CDN / shared hosting) are
    # NOT "likely the same app" just because they answer on one address — that is
    # exactly the heuristic that used to link unrelated neighbours. Skip any IP
    # carrying more than this many hosts.
    max_hosts_per_ip = int(rule.get("max_hosts_per_ip") or 6)

    # host -> titles
    host_titles: dict[str, set[str]] = {}
    for f in findings:
        t = _extract_http_title(f)
        if not t or len(t) < min_len:
            continue
        host = _host_for_finding(f)
        if not host:
            continue
        host_titles.setdefault(host, set()).add(t.lower())

    if len(host_titles) < 2:
        return []

    # IP -> hosts via siblings_same_ip / resolves edges
    ip_hosts: dict[str, set[str]] = {}
    for host in host_titles:
        try:
            sib = graph.siblings_same_ip(host, engagement_id=eid)
        except Exception:
            continue
        ip = (getattr(sib, "ip", None) or "").strip()
        hosts = {host}
        for h in getattr(sib, "siblings", None) or []:
            if isinstance(h, str) and h.strip():
                hosts.add(h.strip().lower())
        if not ip:
            continue
        ip_hosts.setdefault(ip, set()).update(hosts)

    candidates: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()

    for ip, hosts in ip_hosts.items():
        if len(hosts) > max_hosts_per_ip:
            # Too many hosts on this IP → shared infra; title overlap is unreliable.
            continue
        titled = [h for h in hosts if h in host_titles]
        for i, ha in enumerate(titled):
            for hb in titled[i + 1 :]:
                pair = tuple(sorted((ha, hb)))
                if pair in seen_pairs:
                    continue
                best = 0.0
                evidence_titles = ("", "")
                for ta in host_titles[ha]:
                    for tb in host_titles[hb]:
                        ov = _title_overlap(ta, tb)
                        if ov > best:
                            best = ov
                            evidence_titles = (ta, tb)
                if best < min_overlap:
                    continue
                seen_pairs.add(pair)
                evidence = (
                    f"same_ip={ip} title_overlap={best:.2f} "
                    f"titles={evidence_titles[0]!r}~{evidence_titles[1]!r}"
                )
                candidates.append(
                    {
                        "kind": "link",
                        "source": f"host:{ha}",
                        "target": f"host:{hb}",
                        "relation": relation,
                        "evidence": evidence,
                        "evidence_grade": grade,
                        "score": round(best, 3),
                    }
                )
                if len(candidates) >= max_links:
                    return candidates
    return candidates


def _corr_shared_cookie(
    findings: list,
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    max_links = int(rule.get("max_links_per_run") or 8)
    relation = str(rule.get("relation") or "shares_auth")
    grade = str(rule.get("evidence_grade") or "inferred")

    domain_hosts: dict[str, set[str]] = {}
    for f in findings:
        tags = {str(t).lower() for t in (f.tags or [])}
        blob = f"{f.title or ''}\n{f.evidence or ''}\n{f.raw_data or ''}"
        if "cookie" not in tags and "set-cookie" not in blob.lower():
            continue
        m = _COOKIE_DOMAIN.search(blob)
        if not m:
            continue
        cdom = m.group(1).strip().lower().lstrip(".")
        if not cdom or "." not in cdom:
            continue
        host = _host_for_finding(f)
        if not host:
            continue
        domain_hosts.setdefault(cdom, set()).add(host)

    candidates: list[dict[str, Any]] = []
    for cdom, hosts in domain_hosts.items():
        hosts_l = sorted(hosts)
        if len(hosts_l) < 2:
            continue
        base = hosts_l[0]
        for other in hosts_l[1:]:
            candidates.append(
                {
                    "kind": "link",
                    "source": f"host:{base}",
                    "target": f"host:{other}",
                    "relation": relation,
                    "evidence": f"shared Set-Cookie Domain={cdom}",
                    "evidence_grade": grade,
                    "score": 0.6,
                }
            )
            if len(candidates) >= max_links:
                return candidates
    return candidates


def _corr_url_fanout(
    findings: list,
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    from osprey.schemas.finding import FindingType

    min_urls = int(rule.get("min_urls") or 5)
    role = str(rule.get("role") or "app_depth_candidate")
    boost = int(rule.get("boost") or 12)
    max_tags = int(rule.get("max_tags_per_run") or 6)

    # Skip hosts already tagged this engagement
    already = {
        str((f.metadata or {}).get("asset") or "").lower()
        for f in findings
        if "operator_tag" in (f.tags or []) and role in str(f.tags)
    }

    urls_by_host: dict[str, int] = {}
    for f in findings:
        ft = str(getattr(f.finding_type, "value", f.finding_type) or "")
        tags = {str(t).lower() for t in (f.tags or [])}
        if ft != FindingType.URL.value and "js_route" not in tags:
            continue
        host = _host_for_finding(f)
        if not host:
            title = (f.title or "").strip()
            m = _HOST_FROM_URL.match(title)
            host = m.group(1).lower() if m else None
        if not host:
            continue
        urls_by_host[host] = urls_by_host.get(host, 0) + 1

    candidates: list[dict[str, Any]] = []
    for host, count in sorted(urls_by_host.items(), key=lambda x: -x[1]):
        if count < min_urls:
            continue
        if host in already:
            continue
        reason = (
            f"{count} URL/route findings under host — app depth likely worth "
            f"custom probes"
        )
        candidates.append(
            {
                "kind": "tag",
                "asset": f"host:{host}",
                "role": role,
                "boost": boost,
                "evidence": reason,
                "score": min(1.0, count / float(max(min_urls, 1) * 4)),
            }
        )
        if len(candidates) >= max_tags:
            break
    return candidates
