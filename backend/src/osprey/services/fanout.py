"""Explicit sister-domain fan-out (M6) — a thin caller of the one fan-out
primitive in ``fanout_assets.py``.

Commander / operator must call this — nothing auto-chains off domain_hunter.
Default is dry_run; real execution requires confirm=true and dry_run=false.
The domain-specific parts (finding sister gaps, confidence ranking, skipping
domains tool_coverage already marks as done) live here; batch execution
itself — concurrency, dry-run/confirm, per-call RoE — is not reimplemented,
it is delegated to ``fanout_assets.fanout_assets`` like any other caller.
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
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.fanout_assets import FanoutAssetsRequest, fanout_assets
from osprey.services.findings_store import get_findings_store
from osprey.services.tool_coverage_store import get_tool_coverage_store

logger = logging.getLogger(__name__)

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

    gaps = _find_unenumerated_sisters(engagement_id)
    sister_gaps = [g for g in gaps if g.confidence >= request.min_confidence]
    sister_gaps = sorted(sister_gaps, key=lambda g: (-g.confidence, g.domain))[: request.max_domains]
    confidence_by_domain = {g.domain: g.confidence for g in sister_gaps}

    # Domain-specific pre-filter: skip sisters tool_coverage already marks as
    # done for this tool, before the generic fan-out ever sees them.
    coverage = get_tool_coverage_store()
    to_run: list[str] = []
    skip_results: list[FanoutDomainResult] = []
    for gap in sister_gaps:
        domain = (gap.domain or "").strip().lower()
        if not domain:
            continue
        if request.skip_already_marked and coverage.has_run(
            engagement_id=engagement_id, tool_name=tool_name, asset=domain,
        ):
            skip_results.append(
                FanoutDomainResult(
                    domain=domain,
                    gap_confidence=gap.confidence,
                    planned=False,
                    skipped=True,
                    skip_reason=f"soft tool_coverage already marked for {tool_name}",
                )
            )
            continue
        to_run.append(domain)

    batch = await fanout_assets(
        engagement_id,
        FanoutAssetsRequest(
            assets=to_run,
            tool_name=tool_name,
            dry_run=request.dry_run,
            confirm=request.confirm,
            max_assets=max(len(to_run), 1),
            timeout_per_tool=request.timeout_per_tool,
            run_id=request.run_id or "",
        ),
    )

    results: list[FanoutDomainResult] = list(skip_results)
    for item in batch.results:
        results.append(
            FanoutDomainResult(
                domain=item.asset,
                gap_confidence=confidence_by_domain.get(item.asset, 0.0),
                planned=item.planned,
                executed=item.executed,
                skipped=False,
                success=item.success if item.executed else None,
                findings_count=item.findings_count,
                finding_titles=item.finding_titles,
                error=item.error,
                command=item.command,
            )
        )

    note = (
        "Explicit helper only — does not auto-run after domain_hunter. "
        "Does not chain httpx/nmap. Prefer dry_run first."
    )
    if not batch.executed:
        note += " This response is a PREVIEW (dry_run) — set dry_run=false and confirm=true to execute."

    return FanoutSisterResponse(
        engagement_id=engagement_id,
        dry_run=not batch.executed,
        executed=batch.executed,
        tool_name=tool_name,
        domains_considered=len(sister_gaps),
        domains_planned=batch.assets_planned,
        domains_executed=batch.assets_executed,
        domains_skipped=len(skip_results),
        total_findings=batch.total_findings,
        results=results,
        note=note,
        extra={"confirm_required": True},
    )
