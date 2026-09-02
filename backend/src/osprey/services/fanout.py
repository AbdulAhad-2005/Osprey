"""Explicit sister-domain fan-out (M6).

Commander / operator must call this — nothing auto-chains off domain_hunter.
Default is dry_run; real execution requires confirm=true and dry_run=false.
Only runs the chosen subdomain-enum tool (default subfinder). Never httpx/nmap.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.fanout import (
    FanoutDomainResult,
    FanoutSisterRequest,
    FanoutSisterResponse,
)
from osprey.schemas.finding import Finding, FindingType
from osprey.schemas.tools import ToolExecutionRequest
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.tool_coverage_store import get_tool_coverage_store
from osprey.services.tool_execution import execute_tool_request

logger = logging.getLogger(__name__)

_ALLOWED_ENUM_TOOLS = frozenset(
    {
        "subfinder_scan",
        "amass_scan",
        "fierce_scan",
        "dnsenum_scan",
    }
)
_MAX_SISTER_GAPS = 24


@dataclass
class _SisterGap:
    domain: str
    confidence: float


def _is_sister(f: Finding) -> bool:
    if "sister_domain" in (f.tags or []):
        return True
    if f.source_tool == "domain_hunter":
        return True
    role = str((f.metadata or {}).get("role", "")).lower()
    return role in ("sister_domain", "sister", "affiliated")


def _domain_suffix_match(host: str, domain: str) -> bool:
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)


def _find_unenumerated_sisters(engagement_id: str) -> list[_SisterGap]:
    """Sister/affiliate domains discovered (e.g. by domain_hunter) that have no
    structured SUBDOMAIN findings under them yet — candidates for fan-out enum."""
    findings = get_findings_store().list(engagement_id=engagement_id, limit=5000)
    nodes = get_engagement_graph().list_nodes(engagement_id=engagement_id, limit=5000)
    coverage = get_tool_coverage_store().list_for_engagement(engagement_id, limit=2000)

    sisters = [
        f
        for f in findings
        if f.finding_type in (FindingType.HOST, FindingType.SUBDOMAIN) and _is_sister(f)
    ]

    def _has_subdomains_for(domain: str) -> bool:
        for f in findings:
            if f.finding_type == FindingType.SUBDOMAIN and _domain_suffix_match(f.title, domain):
                return True
        for n in nodes:
            if n.asset_type == AssetType.SUBDOMAIN and _domain_suffix_match(n.label, domain):
                return True
        return False

    def _already_marked(domain: str) -> bool:
        return any(rec.tool_name == "subfinder_scan" and rec.asset == domain for rec in coverage)

    out: list[_SisterGap] = []
    seen: set[str] = set()
    for f in sisters:
        domain = f.title.strip().lower()
        if not domain or "." not in domain or domain in seen or _has_subdomains_for(domain):
            continue
        seen.add(domain)
        conf = 0.55
        if f.confidence.value == "confirmed":
            conf = 0.7
        elif f.confidence.value == "hypothesis":
            conf = 0.4
        if _already_marked(domain):
            conf = min(conf, 0.35)
        out.append(_SisterGap(domain=domain, confidence=conf))
        if len(out) >= _MAX_SISTER_GAPS:
            break
    return out


async def enumerate_pending_sisters(
    engagement_id: str,
    request: FanoutSisterRequest | None = None,
) -> FanoutSisterResponse:
    request = request or FanoutSisterRequest()
    eng = get_engagement_store().get(engagement_id)
    if eng is None:
        raise ValueError(f"Engagement not found: {engagement_id}")

    tool_name = (request.tool_name or "subfinder_scan").strip()
    if tool_name not in _ALLOWED_ENUM_TOOLS:
        raise ValueError(
            f"tool_name must be one of {sorted(_ALLOWED_ENUM_TOOLS)} — "
            "fan-out will not run httpx/nmap or other phases"
        )

    will_execute = (not request.dry_run) and request.confirm
    if not request.dry_run and not request.confirm:
        # Soft guard: force preview instead of accidental mass scan
        request = request.model_copy(update={"dry_run": True})
        will_execute = False

    gaps = _find_unenumerated_sisters(engagement_id)
    sister_gaps = [g for g in gaps if g.confidence >= request.min_confidence]
    sister_gaps = sorted(sister_gaps, key=lambda g: (-g.confidence, g.domain))[: request.max_domains]

    coverage = get_tool_coverage_store()
    results: list[FanoutDomainResult] = []
    total_findings = 0
    executed_n = 0
    skipped_n = 0
    planned_n = 0

    for gap in sister_gaps:
        domain = (gap.domain or "").strip().lower()
        if not domain:
            continue

        if request.skip_already_marked and coverage.has_run(
            engagement_id=engagement_id,
            tool_name=tool_name,
            asset=domain,
        ):
            skipped_n += 1
            results.append(
                FanoutDomainResult(
                    domain=domain,
                    gap_confidence=gap.confidence,
                    planned=False,
                    skipped=True,
                    skip_reason=f"soft tool_coverage already marked for {tool_name}",
                )
            )
            continue

        planned_n += 1
        item = FanoutDomainResult(
            domain=domain,
            gap_confidence=gap.confidence,
            planned=True,
        )

        if not will_execute:
            results.append(item)
            continue

        try:
            response = await execute_tool_request(
                ToolExecutionRequest(
                    tool_name=tool_name,
                    params={"domain": domain},
                    engagement_id=engagement_id,
                    run_id=request.run_id,
                    timeout=request.timeout_per_tool,
                    use_recovery=False,
                    record_findings=True,
                )
            )
            item.executed = True
            item.success = response.success
            item.findings_count = len(response.finding_titles or [])
            item.finding_titles = list(response.finding_titles or [])[:20]
            item.command = response.command or ""
            item.error = response.error or ""
            total_findings += item.findings_count
            executed_n += 1
        except Exception as exc:
            logger.exception("fan-out failed for %s", domain)
            item.executed = True
            item.success = False
            item.error = str(exc)
            executed_n += 1
        results.append(item)

    note = (
        "Explicit helper only — does not auto-run after domain_hunter. "
        "Does not chain httpx/nmap. Prefer dry_run first."
    )
    if request.dry_run or not will_execute:
        note += " This response is a PREVIEW (dry_run) — set dry_run=false and confirm=true to execute."

    return FanoutSisterResponse(
        engagement_id=engagement_id,
        dry_run=not will_execute,
        executed=will_execute,
        tool_name=tool_name,
        domains_considered=len(sister_gaps),
        domains_planned=planned_n,
        domains_executed=executed_n,
        domains_skipped=skipped_n,
        total_findings=total_findings,
        results=results,
        note=note,
        extra={
            "confirm_required": True,
            "allowed_tools": sorted(_ALLOWED_ENUM_TOOLS),
        },
    )
