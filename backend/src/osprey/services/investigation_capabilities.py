"""Granular backend capabilities for a harness-owned investigation loop.

This module exposes current opportunities and executes one bounded choice. It
contains no root loop and no target parser: every subject is resolved from a
stable engagement-graph asset id selected from the current revision.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Diagnostic-only cache of the state basis behind each recently-issued
# revision, per engagement — never consulted to decide anything, only to
# explain a 409 (stale investigation revision) when one fires. Live reports
# of a persistent replan loop (e.g. a failed opportunity that keeps losing
# the race after a long-running attempt) had no way to show WHAT actually
# changed between two list_step() calls a few hundred milliseconds apart —
# only that the opaque digest differed. Small and bounded: a handful of
# recent revisions per engagement, dropped as new ones arrive.
_REVISION_BASIS_CACHE: dict[str, dict[str, dict[str, Any]]] = {}
_REVISION_CACHE_MAX_PER_ENGAGEMENT = 4


def _remember_revision_basis(eid: str, revision: str, basis: dict[str, Any]) -> None:
    bucket = _REVISION_BASIS_CACHE.setdefault(eid, {})
    bucket[revision] = basis
    while len(bucket) > _REVISION_CACHE_MAX_PER_ENGAGEMENT:
        bucket.pop(next(iter(bucket)), None)


def diagnose_revision_mismatch(eid: str, expected_revision: str, current_revision: str) -> str:
    """Best-effort explanation for a 409 — which part of revision_basis
    (nodes/opportunities/active_jobs) actually moved, if we still have the
    basis behind both revisions cached in this process (list_step() caches
    its own basis every call, so the "current" side is always available;
    the "expected" side is only there if it's one of the last few revisions
    issued for this engagement)."""
    bucket = _REVISION_BASIS_CACHE.get(eid) or {}
    prior = bucket.get(expected_revision)
    current_basis = bucket.get(current_revision)
    if prior is None or current_basis is None:
        return (
            f"{expected_revision} -> {current_revision}: prior basis not retained "
            "(different process/restart, or more than a few revisions have elapsed since)"
        )
    changed = [key for key in ("nodes", "opportunities", "active_jobs") if prior.get(key) != current_basis.get(key)]
    return f"{expected_revision} -> {current_revision}: changed={changed or '[digest differs but no tracked field does]'}"

from osprey.schemas.engagement_graph import AssetNode, AssetType
from osprey.schemas.investigation import (
    CapabilityKind,
    CapabilityResult,
    InvestigationOpportunity,
    InvestigationStep,
    OpportunitySubject,
    StepStatus,
)
from osprey.schemas.jobs import JobKind, JobStatus

_ASSET_BATCH = 15

# Deliberate per-stage execution ceilings, restored here from the pre-atomic
# engine (deleted with run_expansion_pass in Plan 18 Workstream A, without
# being re-applied at the time — the actual cause of a plain dnsenum_scan
# call running for the better part of an hour: no ceiling here means a hung
# tool inherits the execution kernel's generic 900s default, tripled by the
# kernel's own retry-on-timeout behavior). A short-running, apex-level OSINT
# lookup and a full nmap sweep should never share one blanket budget.
_DOMAIN_ONLY_TIMEOUT = 60  # sister/associated-domain + apex OSINT (whois, dnsenum, crt.sh, domain_hunter)
# These are the tool KILL budgets. They are deliberately GENEROUS: a pentest
# enumerator (amass/gau over 4 providers/gobuster-dns over a wordlist) is
# legitimately minutes-long — slow is not broken, and killing a healthy tool at
# ~2 min throws away real coverage and reports a false failure (observed: gau
# killed at 120s, amass finishing right at the 120s edge). These are a safety
# net against a genuinely-hung process, not a "slow = fail" deadline. The real
# fix (plan 19 Part B) is the driver backgrounding a slow job and continuing,
# so a long tool never blocks the engine and is never killed for being slow;
# until then these budgets at least let the common slow tools complete.
_SUBDOMAIN_ENUM_TIMEOUT = 420  # passive wordlist tools (subfinder/amass/gau/wayback/tlsx)
_DNS_BRUTE_TIMEOUT = 420  # active DNS brute force + permutation resolution
_DNS_RECORD_TIMEOUT = 45  # a single dnsx_resolve / email_security_probe call
_LIVE_HOST_TIMEOUT = 120  # host_expansion battery (httpx/naabu/tech-stack/waf/cdn)
_WEB_DEPTH_TIMEOUT = 240  # content discovery / JS recon / policy files
_SERVICE_SCAN_TIMEOUT = 240  # nmap service/version scan or connect-scan retry
_CONTACT_TIMEOUT = 90  # OSINT contact harvest + breach/passive-intel lookups


def _digest(value: Any, *, length: int = 20) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:length]


def _subject(node: AssetNode) -> OpportunitySubject:
    return OpportunitySubject(
        asset_id=node.id,
        asset_type=node.asset_type.value,
        label=node.label,
        evidence_ids=list(node.observation_ids),
        coverage={
            key: node.metadata.get(key)
            for key in (
                "related_domains_discovered", "subdomains_enumerated", "dns_resolved",
                "live_probed", "host_profiled", "host_expanded",
            )
            if key in node.metadata
        },
    )


def _opportunity(
    capability: CapabilityKind,
    nodes: list[AssetNode],
    *,
    reason: str,
    priority: int,
    evidence: dict[str, Any] | None = None,
    priority_factors: dict[str, float] | None = None,
    cost: str = "low",
    risk: str = "passive",
) -> InvestigationOpportunity:
    basis = {
        "capability": capability.value,
        "subjects": sorted(n.id for n in nodes),
        "evidence": evidence or {},
    }
    return InvestigationOpportunity(
        id=f"opp_{_digest(basis)}",
        capability=capability,
        reason=reason,
        priority=priority,
        priority_factors=priority_factors or {},
        cost=cost,
        risk=risk,
        subjects=[_subject(n) for n in nodes],
        evidence=evidence or {},
    )


def _tool_opportunity(
    tool: str,
    node: AssetNode,
    *,
    param: str = "",
    capability: CapabilityKind,
    reason: str,
    base: int,
    priority_ctx: Any,
    extra: dict[str, Any] | None = None,
    direct_params: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    additional_args: str = "",
    timeout: int = 0,
    cost: str = "low",
    risk: str = "passive",
) -> InvestigationOpportunity:
    """One opportunity == exactly one real tool call on one asset — the only
    unit of execution this module ever produces. A stage that used to fire
    several different tools behind one capability (the old
    ENUMERATE_SUBDOMAINS/PROFILE_HOST_SERVICES) now yields one opportunity
    per tool, so whoever is choosing — an LLM operator or the deterministic
    driver — sees and authorizes every real action individually, exactly as
    if they had called the tool directly themselves.

    ``param``/``extra`` cover the common case: the tool takes the node's
    label under some key (``target``/``domain``/...). ``direct_params``
    covers the rest — a tool whose params don't derive from the node's label
    at all (e.g. an OSINT enrichment rule where ``holehe`` needs the matched
    finding's actual email string, not a hostname). ``node`` is still
    attached as the opportunity's subject either way, for graph/priority
    purposes; ``direct_params`` fully replaces the ``{param: node.label}``
    construction when given, rather than being merged with it.

    ``timeout`` is the deliberate per-stage execution ceiling — an explicit
    argument here wins; otherwise a ``timeout`` key in ``extra`` (an
    expansion.yaml stage entry's own field, e.g. ``tech_stack_analyze``'s
    ``timeout: 300``) is used; 0 means "no ceiling declared, caller applies
    its own generic default." A hung tool with no ceiling at all inherits
    the execution kernel's generic 900s budget, tripled by its own
    retry-on-timeout behavior — this is what actually caused a plain
    ``dnsenum_scan`` call to run for the better part of an hour.
    """
    from osprey.services import priority as priority_mod

    score = priority_mod.score_asset(node, priority_ctx)
    adjustment = round(max(0.0, min(20.0, score.total * 3.0)))
    extra = extra or {}
    resolved_timeout = timeout or int(extra.get("timeout") or 0)
    if direct_params is not None:
        params = dict(direct_params)
    else:
        params = {param: node.label, **{k: v for k, v in extra.items() if k != "timeout"}}
    basis = {
        "capability": capability.value, "tool": tool, "subject": node.id,
        "params": params, "additional_args": additional_args, "evidence": evidence or {},
    }
    return InvestigationOpportunity(
        id=f"opp_{_digest(basis)}",
        capability=capability,
        reason=reason,
        priority=base + adjustment,
        priority_factors=score.factors.model_dump(),
        cost=cost,
        risk=risk,
        subjects=[_subject(node)],
        evidence=evidence or {},
        timeout=resolved_timeout,
        tool=tool,
        params=params,
        additional_args=additional_args,
    )


def _analytical_opportunity(
    capability: CapabilityKind,
    nodes: list[AssetNode],
    *,
    reason: str,
    priority: int,
    evidence: dict[str, Any] | None = None,
) -> InvestigationOpportunity:
    """The three capabilities that touch no Kali tool at all — pure store
    recomputation (promotion/anomaly-detection/candidate-refresh). Batching
    several subjects into one of these is fine: nothing here is a real
    pentest action against the target, so nothing is hidden by grouping the
    bookkeeping scope. See CapabilityKind's docstring."""
    return _opportunity(capability, nodes, reason=reason, priority=priority, evidence=evidence)


def _current_nodes(engagement_id: str) -> list[AssetNode]:
    from osprey.services.engagement_graph import get_engagement_graph

    return get_engagement_graph().list_nodes(engagement_id=engagement_id, limit=20_000)


def expansion_sister_is_eligible(node: AssetNode) -> bool:
    """Use the expansion kernel's configured trust policy for sister domains.

    Keeping this decision in one place prevents the harness opportunity layer
    from widening scope more aggressively than the proven execution kernel.
    """
    from osprey.services.surface_expansion import _sister_expandable

    return _sister_expandable(node)


def _active_jobs(engagement_id: str):
    from osprey.services.job_store import get_job_store

    return [
        job for job in get_job_store().list_for_engagement(engagement_id, limit=100)
        if job.kind == JobKind.INVESTIGATION_STEP
        and job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
    ]


# A single identical action (same tool, same subjects, same evidence basis)
# that keeps failing is retried at most this many times before the engine
# stops re-offering it and moves on — matching ExploitCandidateStore's own
# _MAX_ATTEMPTS. Not a graph "exhausted" boolean: the opportunity id embeds
# its evidence basis, so genuinely new evidence produces a NEW id that runs
# again; this only caps repeated *identical* failures.
_MAX_OPPORTUNITY_FAILURES = 2


def _failed_opportunity_ids(engagement_id: str) -> set[str]:
    """Opportunity ids that have failed at least ``_MAX_OPPORTUNITY_FAILURES``
    times and must stop being re-offered.

    ``_successful_opportunity_ids`` only records what SUCCEEDED, so an action
    that always fails (e.g. ``gau_discovery`` timing out against unreachable
    external services, or a tool the container has no egress for) was
    re-offered on every ``list_step`` and re-picked by the deterministic
    driver forever — a real, observed infinite retry loop, not a tool bug.
    Capping identical failures here is the system-level fix, applied where
    every driver (CLI ``--engine``, supervised, any deterministic MCP use)
    reads its opportunities, not patched into one caller.

    In-memory job history is bounded and clears on restart, which is the
    intended behavior: a restart (or genuinely new evidence, which mints a
    new opportunity id) is a legitimate fresh chance.
    """
    from collections import Counter

    from osprey.services.job_store import get_job_store

    fail_counts: Counter[str] = Counter()
    for job in get_job_store().list_for_engagement(engagement_id, limit=500):
        if job.kind != JobKind.INVESTIGATION_STEP or not job.opportunity_id:
            continue
        # Two shapes of failure, both counted: the normal path where the
        # capability's tool reported success=False (job COMPLETED, success
        # False — a routine 502/timeout, job_store.py's INVESTIGATION_STEP
        # branch keeps these COMPLETED on purpose), and the exception path
        # where execute_capability itself raised (job FAILED, success None).
        failed = job.status == JobStatus.FAILED or (
            job.status == JobStatus.COMPLETED and job.success is False
        )
        if failed:
            fail_counts[job.opportunity_id] += 1
    return {oid for oid, n in fail_counts.items() if n >= _MAX_OPPORTUNITY_FAILURES}


def _successful_opportunity_ids(engagement_id: str) -> set[str]:
    """Durable execution history is the coverage record for harness actions.

    A capability is complete only when its job completed successfully.  Tool
    failure must never be converted into a graph boolean that makes the
    surface look exhausted.  Opportunity ids include their evidence basis, so
    materially new evidence produces a new action even when the subjects are
    unchanged.
    """
    from osprey.services.job_store import get_job_store

    completed = {
        job.opportunity_id
        for job in get_job_store().list_for_engagement(engagement_id, limit=200)
        if job.kind == JobKind.INVESTIGATION_STEP
        and job.status == JobStatus.COMPLETED
        and job.success is not False
        and job.opportunity_id
    }
    # The in-memory job store is intentionally bounded and empty after a
    # restart. Scan-run history is the durable decision journal, so completed
    # work must also be recovered from it or the harness will repeat old steps.
    from osprey.services.scan_run_store import get_scan_run_store
    completed.update(
        get_scan_run_store().successful_investigation_opportunity_ids(engagement_id)
    )
    return completed


def list_step(engagement_id: str, run_id: str = "") -> InvestigationStep:
    """Return a read-only, revisioned set of currently executable opportunities.

    Every opportunity here is exactly one real tool call (or, for the three
    analytical kinds, one pure-store operation) — never a batch. A stage that
    used to run several tools behind one capability (e.g. the old
    ENUMERATE_SUBDOMAINS firing subfinder+amass+gobuster together, or
    PROFILE_HOST_SERVICES firing web-depth+origin-attribution+shodan+service-
    scan all at once) now yields one opportunity per tool, so nothing is ever
    hidden from whoever is choosing — an LLM operator or the deterministic
    driver see and authorize every real action individually, exactly like
    calling the tool directly would.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return InvestigationStep(
            engagement_id="", run_id=run_id, revision=_digest("missing"),
            status=StepStatus.BLOCKED, state_summary="engagement_id required",
        )

    nodes = _current_nodes(eid)
    active = _active_jobs(eid)
    opportunities: list[InvestigationOpportunity] = []

    from osprey.services import priority

    priority_ctx = priority.build_context(eid)

    edges = []
    if nodes:
        from osprey.services.engagement_graph import get_engagement_graph

        edges = get_engagement_graph().list_edges(engagement_id=eid, limit=50_000)
    outgoing: dict[str, set[str]] = {}
    incoming: dict[str, set[str]] = {}
    for edge in edges:
        outgoing.setdefault(edge.source_id, set()).add(edge.relationship)
        incoming.setdefault(edge.target_id, set()).add(edge.relationship)

    id_to_node = {n.id: n for n in nodes}
    resolved_ip_of: dict[str, str] = {}
    for edge in edges:
        if edge.relationship == "resolves_to":
            target_node = id_to_node.get(edge.target_id)
            if target_node is not None and target_node.asset_type == AssetType.IP:
                resolved_ip_of.setdefault(edge.source_id, target_node.label)

    domains = [n for n in nodes if n.asset_type == AssetType.DOMAIN]
    enum_nodes = [
        n for n in nodes
        if n.asset_type in (AssetType.DOMAIN, AssetType.HOST)
        and (
            n.asset_type == AssetType.DOMAIN
            or (n.metadata.get("role") == "sister_domain" and expansion_sister_is_eligible(n))
        )
    ]
    from osprey.services.surface_expansion import (
        _MAX_AUTO_SWEEP_ADDRESSES,
        _MIN_ORIGIN_CONFIDENCE,
        _origin_confidence,
    )

    resolve_nodes = [n for n in nodes if n.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)]
    # A low-confidence origin-IP guess (cdn_origin_probe's heuristic score
    # below threshold) must be held back from port-scanning, not treated the
    # same as a confirmed live host — "merely finding an IP near the target
    # is not origin attribution." Every other node type is unaffected.
    held_back_origin_ids = {
        n.id for n in nodes
        if n.metadata.get("role") == "origin_candidate"
        and _origin_confidence(n) < _MIN_ORIGIN_CONFIDENCE
    }
    probe_nodes = [
        n for n in nodes
        if n.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.HOST, AssetType.IP)
        and (n.asset_type == AssetType.IP or "resolves_to" in outgoing.get(n.id, set()))
        and n.id not in held_back_origin_ids
    ]
    profile_nodes = [
        n for n in nodes
        if n.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.HOST, AssetType.IP)
        and bool(
            outgoing.get(n.id, set()) & {"has_port", "runs_service", "runs_tech"}
            or incoming.get(n.id, set()) & {"hosted_on"}
        )
    ]
    ip_nodes = [n for n in nodes if n.asset_type == AssetType.IP]

    from osprey.services.surface_expansion import (
        _generate_permutation_candidates,
        _host_has_services,
        _host_is_live_web,
        _host_open_ports,
        _installed_steps,
        _permutation_patterns,
        _phase_enabled,
    )
    from osprey.services.engagement_graph import get_engagement_graph
    from osprey.services.tool_coverage_store import get_tool_coverage_store
    from osprey.services.target_utils import is_ipv4, resolve_ipv4

    graph = get_engagement_graph()
    coverage = get_tool_coverage_store()

    # --- Sister/associated-domain discovery + apex OSINT — one opportunity
    # per (tool, domain), sourced straight from expansion.yaml's
    # sister_discovery + domain_only sections. ---
    for n in domains:
        for tool, param, extra in _installed_steps("sister_discovery") + _installed_steps("domain_only"):
            # A per-entry "timeout" in expansion.yaml (e.g. domain_hunter's —
            # it queries ~10 external sources, structurally heavier than its
            # single-source bucket-mates) overrides the section's shared
            # default; everything else keeps the same 60s ceiling as before.
            opportunities.append(_tool_opportunity(
                tool, n, param=param, capability=CapabilityKind.DISCOVER_RELATED_DOMAINS,
                reason=f"{n.label} has not had {tool} run for associated-domain discovery.",
                base=100, priority_ctx=priority_ctx, extra=extra,
                timeout=int(extra.get("timeout") or 0) or _DOMAIN_ONLY_TIMEOUT,
            ))

    # --- OSINT contact harvest (theharvester/web_contact_harvest) + env-keyed
    # breach/passive-intel tools (config/breach_intel_tools.yaml) — one
    # opportunity per (tool, apex domain), restricted to apexes this
    # engagement actually owns (an OSINT tool's canned/third-party test data
    # must never make an unrelated domain look like a worked asset). This is
    # the *initial* harvest step — tech_dispatch.yaml's osint_* rules only
    # pivot once a person/email/phone already exists as a finding; nothing
    # else ever starts the harvest.
    import os

    from osprey.services.surface_expansion import (
        _CONTACT_DISCOVERY_TOOLS,
        _breach_intel_tool_entries,
        _is_expandable_apex,
    )

    apex_label = domains[0].label if domains else ""
    owned_domains = [n for n in domains if _is_expandable_apex(n, target_label=apex_label)]
    active_breach_tools = [
        (tool, param) for env_var, tool, param in _breach_intel_tool_entries()
        if os.getenv(env_var, "").strip()
    ]
    for n in owned_domains:
        for tool, param in _CONTACT_DISCOVERY_TOOLS:
            if coverage.has_run(engagement_id=eid, tool_name=tool, asset=n.label) is None:
                opportunities.append(_tool_opportunity(
                    tool, n, param=param, capability=CapabilityKind.HARVEST_CONTACTS,
                    reason=f"{n.label} has not had OSINT contact harvest ({tool}) run.",
                    base=50, priority_ctx=priority_ctx, timeout=_CONTACT_TIMEOUT,
                ))
        for tool, param in active_breach_tools:
            if coverage.has_run(engagement_id=eid, tool_name=tool, asset=n.label) is None:
                opportunities.append(_tool_opportunity(
                    tool, n, param=param, capability=CapabilityKind.HARVEST_CONTACTS,
                    reason=f"{n.label} has a keyed breach/passive-intel source ({tool}) not yet queried.",
                    base=52, priority_ctx=priority_ctx, timeout=_CONTACT_TIMEOUT,
                ))

    # --- Subdomain enumeration — passive wordlist tools, then DNS brute
    # force, then permutation-mutated candidates. One opportunity per
    # (tool, domain); permutations are one dnsx_resolve call per domain. ---
    for n in enum_nodes:
        for tool, param, extra in _installed_steps("wordlist_discovery"):
            opportunities.append(_tool_opportunity(
                tool, n, param=param, capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
                reason=f"{n.label} has unenumerated subdomain surface ({tool}).",
                base=95, priority_ctx=priority_ctx, extra=extra, timeout=_SUBDOMAIN_ENUM_TIMEOUT,
            ))
        if not n.metadata.get("dns_bf_done"):
            for tool, param, extra in _installed_steps("dns_bruteforce"):
                opportunities.append(_tool_opportunity(
                    tool, n, param=param, capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
                    reason=f"{n.label} has not had active DNS brute force yet.",
                    base=93, priority_ctx=priority_ctx, extra=extra, timeout=_DNS_BRUTE_TIMEOUT,
                ))
            candidates = _generate_permutation_candidates(graph, eid, n.label, _permutation_patterns())
            if candidates:
                opportunities.append(_tool_opportunity(
                    "dnsx_resolve", n, param="target", capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
                    reason=f"{len(candidates)} permutation candidate(s) generated from known subdomains of {n.label}.",
                    base=92, priority_ctx=priority_ctx,
                    evidence={"candidates": sorted(candidates)},
                    extra={"target": "\n".join(candidates)}, timeout=_DNS_BRUTE_TIMEOUT,
                ))

    # --- DNS resolution + email-security posture. ---
    for n in resolve_nodes:
        opportunities.append(_tool_opportunity(
            "dnsx_resolve", n, param="target", capability=CapabilityKind.RESOLVE_ASSETS,
            reason=f"{n.label} needs DNS resolution before host probing.",
            base=90, priority_ctx=priority_ctx, timeout=_DNS_RECORD_TIMEOUT,
        ))
        if n.asset_type == AssetType.DOMAIN:
            opportunities.append(_tool_opportunity(
                "email_security_probe", n, param="domain", capability=CapabilityKind.RESOLVE_ASSETS,
                reason=f"{n.label} has not had SPF/DKIM/DMARC posture checked.",
                base=88, priority_ctx=priority_ctx, timeout=_DNS_RECORD_TIMEOUT,
            ))

    # --- Live-host probing (httpx/naabu/tech-stack/WAF/CDN). ---
    for n in probe_nodes:
        for tool, param, extra in _installed_steps("host_expansion"):
            opportunities.append(_tool_opportunity(
                tool, n, param=param, capability=CapabilityKind.PROBE_LIVE_ASSETS,
                reason=f"{n.label} is resolved but not yet probed ({tool}).",
                base=85, priority_ctx=priority_ctx, extra=extra, timeout=_LIVE_HOST_TIMEOUT,
                cost="medium", risk="active",
            ))

    # --- Everything that used to be bundled into the monolithic
    # PROFILE_HOST_SERVICES capability — now one opportunity per tool per
    # host, each independently gated on real recorded state (never "always
    # run again"), so nothing repeats and nothing is hidden. ---
    for n in profile_nodes:
        host = n.label
        host_ip = n.label if n.asset_type == AssetType.IP else resolved_ip_of.get(n.id)

        if _phase_enabled("web_depth") and _host_is_live_web(eid, host=host):
            for tool, param, extra in _installed_steps("web_depth"):
                opportunities.append(_tool_opportunity(
                    tool, n, param=param, capability=CapabilityKind.PROBE_WEB_DEPTH,
                    reason=f"{host} serves HTTP and has not had web-depth probing ({tool}).",
                    base=80, priority_ctx=priority_ctx, extra=extra, timeout=_WEB_DEPTH_TIMEOUT,
                    cost="medium", risk="active",
                ))

        if coverage.has_run(engagement_id=eid, tool_name="origin_ip_attribution", asset=host) is None:
            opportunities.append(_tool_opportunity(
                "origin_ip_attribution", n, param="domain", capability=CapabilityKind.ATTRIBUTE_ORIGIN,
                reason=f"{host} has not had origin-IP attribution run.",
                base=78, priority_ctx=priority_ctx, timeout=_DOMAIN_ONLY_TIMEOUT, cost="medium", risk="active",
            ))

        open_ports = _host_open_ports(eid, host=host, ip=host_ip)
        if open_ports:
            opportunities.append(_tool_opportunity(
                "nmap_service_scan", n, param="target", capability=CapabilityKind.VERSION_SERVICES,
                reason=f"{host} has open ports without a version/service scan.",
                base=80, priority_ctx=priority_ctx,
                evidence={"ports": open_ports},
                additional_args=f"-p {','.join(open_ports)}", timeout=_SERVICE_SCAN_TIMEOUT,
                cost="medium", risk="active",
            ))

        if not _host_has_services(eid, host=host, ip=host_ip):
            connect_flags = (
                f"-Pn -sT -sV -p {','.join(open_ports)} --max-retries 1 --host-timeout 90s" if open_ports
                else "-Pn -sT -sV --top-ports 100 --max-retries 1 --host-timeout 90s"
            )
            opportunities.append(_tool_opportunity(
                "nmap_custom_scan", n, param="target", capability=CapabilityKind.RETRY_CONNECT_SCAN,
                reason=f"{host} has no service profile yet — SYN discovery may be firewalled.",
                base=76, priority_ctx=priority_ctx,
                additional_args=connect_flags, timeout=_SERVICE_SCAN_TIMEOUT,
                cost="medium", risk="active",
            ))

    shodan_keyed = bool(os.getenv("SHODAN_API_KEY", "").strip())
    for n in ip_nodes:
        if (
            shodan_keyed and is_ipv4(n.label)
            and coverage.has_run(engagement_id=eid, tool_name="shodan_host_info", asset=n.label) is None
        ):
            opportunities.append(_tool_opportunity(
                "shodan_host_info", n, param="ip", capability=CapabilityKind.QUERY_PASSIVE_INTEL,
                reason=f"{n.label} has no passive Shodan host intel yet.",
                base=60, priority_ctx=priority_ctx, timeout=_DOMAIN_ONLY_TIMEOUT,
            ))

    # --- Network-wide vulnerability scan — deliberate, config-gated phase
    # (phases.vuln_scan in expansion.yaml), one opportunity engagement-wide,
    # deduped the same way the old inline call was (tool_coverage.has_run). ---
    from osprey.services.engagement_store import get_engagement_store

    eng = get_engagement_store().get(eid)
    eng_target = eng.target if eng else ""
    if eng_target and _phase_enabled("vuln_scan") and domains:
        scan_target = resolve_ipv4(eng_target) or eng_target
        if coverage.has_run(engagement_id=eid, tool_name="nmap_custom_scan", asset=scan_target) is None:
            all_ports = sorted(
                {p for n in nodes for p in _host_open_ports(eid, host=n.label, ip=resolved_ip_of.get(n.id))},
                key=lambda x: int(x) if x.isdigit() else 0,
            )
            if all_ports:
                opportunities.append(_tool_opportunity(
                    "nmap_custom_scan", domains[0], param="target",
                    capability=CapabilityKind.SCAN_NETWORK_VULNERABILITIES,
                    reason="Recon has established ports; comprehensive vuln/vulners scan has not run.",
                    base=65, priority_ctx=priority_ctx,
                    evidence={"ports": all_ports, "scan_target": scan_target},
                    extra={"target": scan_target},
                    additional_args=f'-Pn -sV --script "vuln,vulners" -p {",".join(all_ports)}',
                    timeout=600,  # matches phase_supervisor's own inline call for the same scan
                    cost="high", risk="active",
                ))

    # --- Tech-aware vulnerability dispatch — already atomic (one suggestion
    # = one tool); now carries tool/params directly instead of round-tripping
    # through capability_input/DispatchSuggestion reconstruction. ---
    from osprey.services.heuristic_engine import NON_AUTONOMOUS_CATEGORIES, _category_of
    from osprey.services.tech_dispatch import suggest_dispatch

    # No phase-unlock gate here (plan 19: phases never gate mandatory work).
    # suggest_dispatch is self-gating — a rule only fires when the mechanical
    # facts it keys off actually exist (a TECHNOLOGY observation for nuclei, an
    # injection-point tag for sqlmap, a live host in the graph, ...). Gating it
    # behind a separate priority-score "vuln unlock" was exactly the judgment-
    # on-mandatory-work anti-pattern that (together with dispatch reading the
    # empty findings store) kept the deterministic floor from ever reaching
    # vulnerability analysis. The NON_AUTONOMOUS_CATEGORIES filter below is the
    # one gate that stays: it's the RoE/exploit safety boundary, not a phase gate.
    root_subject = domains[:1] or nodes[:1]
    label_to_node = {n.label: n for n in nodes}
    if root_subject:
        for suggestion in suggest_dispatch(engagement_id=eid, run_id=run_id):
            if not suggestion.default_tool or _category_of(suggestion.default_tool) in NON_AUTONOMOUS_CATEGORIES:
                continue
            # A per-match suggestion (Plan 18 Workstream B) names the real
            # asset that matched — resolve it; an engagement-wide suggestion
            # (subject_id empty, the pre-Workstream-B default for any rule
            # not yet annotated `scope: per_match`) keeps falling back to the
            # apex, unchanged.
            subject_node = label_to_node.get(suggestion.subject_id) if suggestion.subject_id else None
            subject = subject_node or root_subject[0]
            opportunities.append(_tool_opportunity(
                suggestion.default_tool, subject,
                param="target" if not suggestion.params else "",
                direct_params=dict(suggestion.params) if suggestion.params else None,
                capability=CapabilityKind.ASSESS_VULNERABILITY,
                reason=suggestion.reason,
                base=max(60, suggestion.priority), priority_ctx=priority_ctx,
                additional_args=suggestion.additional_args,
                evidence={"signal": suggestion.signal, "subject": suggestion.subject_id},
                cost="medium", risk="active",
            ))

    # --- Netblock/subnet-sibling sweep — pure graph mutation (no tool call),
    # so it is itself an analytical capability: an asn_enum-surfaced small
    # CIDR (<=_MAX_AUTO_SWEEP_ADDRESSES) expands into individual IP nodes
    # that then flow into PROBE_LIVE_ASSETS/RESOLVE_ASSETS like any other IP.
    # A CIDR larger than the bound is recorded (asn_enum's own finding
    # already does that) but never auto-swept — a /16+ sweep is an operator
    # call, not a mechanical one. One opportunity per unswept CIDR so an
    # operator sees and authorizes each subnet pivot individually.
    from osprey.schemas.observation import ObservationType as _OTAsn
    from osprey.services.observation_store import get_observation_store as _get_obs_store

    already_swept_cidrs = {
        n.metadata.get("cidr")
        for n in nodes
        if n.asset_type == AssetType.IP and n.metadata.get("role") == "subnet_sibling"
    }
    # asn_enum records each announced BGP prefix as an ASN observation carrying
    # details["cidr"] (parsers/recon_network.py) — read those, never findings:
    # the no-LLM path creates no findings, so sourcing the sweep from
    # findings_store meant it silently never ran (plan 19 / 19a).
    for obs in _get_obs_store().list_by_type(eid, _OTAsn.ASN, limit=200):
        cidr = str(obs.details.get("cidr") or "").strip()
        if not cidr or cidr in already_swept_cidrs:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.num_addresses > _MAX_AUTO_SWEEP_ADDRESSES:
            continue
        subject = domains[0] if domains else (nodes[0] if nodes else None)
        if subject is None:
            continue
        opportunities.append(_analytical_opportunity(
            CapabilityKind.SWEEP_NETBLOCK, [subject],
            reason=f"{cidr} is a small netblock ({network.num_addresses} addresses) near an owned IP — sweep into candidate hosts.",
            priority=45, evidence={"cidr": cidr},
        ))

    # --- Analytical capabilities — no tool, pure store operations. ---
    # NO auto-promotion of scanner signals to findings (plan 19): the
    # deterministic floor must manufacture ZERO findings — a scanner match is a
    # scanner_claim observation and stays one; only a brain, citing evidence,
    # files a conclusion. The former PROMOTE_OBSERVATIONS capability (which ran
    # promote_observations with no human in the loop) was the single most
    # dangerous false-positive source and is removed from the engine here.
    if nodes:
        observation_basis = sorted({oid for node in nodes for oid in node.observation_ids})
        opportunities.append(_analytical_opportunity(
            CapabilityKind.DETECT_ANOMALIES, nodes[:_ASSET_BATCH],
            reason="Refresh peer-difference signals after world-state changes.", priority=25,
            evidence={"observation_ids": observation_basis},
        ))
        # Candidates are re-sourced from observations (exploit_pipeline.
        # scan_for_candidates), so the refresh re-runs when OBSERVATIONS change,
        # not findings — the no-LLM path has no findings anyway (plan 19).
        opportunities.append(_analytical_opportunity(
            CapabilityKind.REFRESH_EXPLOIT_CANDIDATES, root_subject or nodes[:1],
            reason="Refresh the evidence-driven candidate queue without exploitation.", priority=20,
            evidence={"observation_ids": observation_basis},
        ))

    done = _successful_opportunity_ids(eid) | _failed_opportunity_ids(eid)
    opportunities = [item for item in opportunities if item.id not in done]
    opportunities.sort(key=lambda item: (-item.priority, item.id))
    revision_basis = {
        "nodes": [
            [n.id, n.updated_at, sorted(n.observation_ids), {
                k: n.metadata.get(k) for k in (
                    "related_domains_discovered", "subdomains_enumerated", "dns_resolved",
                    "live_probed", "host_profiled", "host_expanded", "dns_bf_done",
                )
            }]
            for n in nodes
        ],
        "opportunities": [o.id for o in opportunities],
        "active_jobs": [[j.job_id, j.status.value] for j in active],
    }
    revision = f"rev_{_digest(revision_basis)}"
    _remember_revision_basis(eid, revision, revision_basis)
    if active:
        status = StepStatus.WAITING
        summary = f"{len(active)} bounded investigation job(s) active; {len(opportunities)} opportunity(s) visible."
    elif opportunities:
        status = StepStatus.READY
        summary = f"{len(opportunities)} bounded investigation opportunity(s) ready."
    elif not nodes:
        status = StepStatus.BLOCKED
        summary = "The engagement has no typed graph seed; rebind or repair engagement creation."
    else:
        status = StepStatus.COMPLETE
        summary = "No current bounded investigation opportunities."
    return InvestigationStep(
        engagement_id=eid, run_id=run_id, revision=revision, status=status,
        state_summary=summary, opportunities=opportunities, active_jobs=active,
    )


def _resolve_subjects(engagement_id: str, subject_ids: list[str]) -> list[AssetNode]:
    wanted = set(subject_ids)
    return [n for n in _current_nodes(engagement_id) if n.id in wanted]


async def _execute_tool(
    tool_name: str,
    params: dict[str, Any],
    *,
    engagement_id: str,
    run_id: str,
    additional_args: str = "",
    timeout: int = 0,
) -> dict[str, Any]:
    from osprey.schemas.tools import ToolExecutionRequest
    from osprey.services.tool_execution import execute_tool_request

    response = await execute_tool_request(ToolExecutionRequest(
        tool_name=tool_name, params=params, engagement_id=engagement_id, run_id=run_id,
        additional_args=additional_args, use_recovery=True, record_findings=True,
        timeout=timeout or 900,
    ))
    # Surface timed_out/partial so the reading surface (CLI/dashboard) can tell a
    # healthy-but-slow tool that hit its budget (timed_out, often with partial
    # output kept) apart from a genuine failure. Without these, a slow tool
    # (amass/nuclei/gau/full-nmap) reads as a bare "failed" with no reason — the
    # exact confusion a kill-timeout causes. A timed_out run that still produced
    # output is NOT a failure to the operator; it's partial coverage.
    return {
        "tool": tool_name, "success": bool(response.success),
        "timed_out": bool(response.timed_out),
        "partial": bool(getattr(response, "partial", False)),
        "finding_titles": list(response.finding_titles or []),
        "error": response.error or response.stderr or "",
    }


_ANALYTICAL_KINDS = frozenset({
    CapabilityKind.DETECT_ANOMALIES,
    CapabilityKind.REFRESH_EXPLOIT_CANDIDATES,
    CapabilityKind.SWEEP_NETBLOCK,
})


async def execute_capability(
    *,
    engagement_id: str,
    run_id: str,
    opportunity_id: str,
    capability: str,
    subject_ids: list[str],
    tool: str = "",
    params: dict[str, Any] | None = None,
    additional_args: str = "",
    timeout: int = 0,
    capability_input: dict[str, Any] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> CapabilityResult:
    """Execute exactly ONE opportunity: one tool call, or — for the three
    analytical kinds — one pure-store operation. Never a batch: this
    function contains no ``asyncio.gather`` of several different tools
    anymore. Every real action an operator (LLM or deterministic driver)
    authorizes is exactly the action that runs, nothing more, nothing
    hidden behind it.
    """
    kind = CapabilityKind(capability)
    nodes = _resolve_subjects(engagement_id, subject_ids)
    if len(nodes) != len(set(subject_ids)):
        return CapabilityResult(
            engagement_id=engagement_id, run_id=run_id, opportunity_id=opportunity_id,
            capability=kind, success=False, stopped_reason="subject_missing",
        )

    before_nodes = _current_nodes(engagement_id)
    before_ids = {n.id for n in before_nodes}
    before_evidence_ids = {oid for node in before_nodes for oid in node.observation_ids}
    results: list[dict[str, Any]] = []

    if kind in _ANALYTICAL_KINDS:
        if kind == CapabilityKind.DETECT_ANOMALIES:
            from osprey.services.anomaly_detection import detect_peer_anomalies

            found = detect_peer_anomalies(engagement_id)
            results.append({"anomalies": len(found), "observation_ids": [o.id for o in found]})
            if on_progress is not None:
                on_progress(f"RESULT::investigation: detected {len(found)} peer anomaly signal(s)")
        elif kind == CapabilityKind.REFRESH_EXPLOIT_CANDIDATES:
            from osprey.services.exploit_pipeline import scan_for_candidates

            found = scan_for_candidates(engagement_id=engagement_id, run_id=run_id)
            results.append({"candidates": len(found), "candidate_ids": [c.id for c in found]})
            if on_progress is not None:
                on_progress(f"RESULT::investigation: refreshed {len(found)} exploit candidate(s)")
        else:  # SWEEP_NETBLOCK
            from osprey.services.engagement_graph import get_engagement_graph
            from osprey.services.surface_expansion import _MAX_AUTO_SWEEP_ADDRESSES

            cidr = str((capability_input or {}).get("cidr") or "").strip()
            created: list[str] = []
            try:
                network = ipaddress.ip_network(cidr, strict=False) if cidr else None
            except ValueError:
                network = None
            if network is not None and network.num_addresses <= _MAX_AUTO_SWEEP_ADDRESSES:
                graph = get_engagement_graph()
                for host_ip in network.hosts():
                    # ptr_checked=True at creation: siblings still get the
                    # full live-host treatment via PROBE_LIVE_ASSETS — this
                    # only skips re-running PTR+asn_enum per sibling, which
                    # would otherwise recursively discover more netblocks
                    # from every IP in an already-discovered one and never
                    # terminate.
                    graph.ensure_node(
                        engagement_id=engagement_id, asset_type=AssetType.IP, label=str(host_ip),
                        metadata={"role": "subnet_sibling", "cidr": cidr, "ptr_checked": True},
                    )
                    created.append(str(host_ip))
            results.append({"cidr": cidr, "hosts_created": len(created)})
            if on_progress is not None:
                on_progress(f"RESULT::investigation: swept {cidr or '(missing cidr)'} into {len(created)} host candidate(s)")
        success = True
    else:
        if not tool:
            return CapabilityResult(
                engagement_id=engagement_id, run_id=run_id, opportunity_id=opportunity_id,
                capability=kind, success=False, stopped_reason="capability_unavailable",
            )
        if on_progress is not None:
            on_progress(f"investigation: running {tool}")
        result = await _execute_tool(
            tool, dict(params or {}), engagement_id=engagement_id, run_id=run_id,
            additional_args=additional_args, timeout=timeout,
        )
        results.append(result)
        success = bool(result.get("success"))
        if on_progress is not None:
            outcome = "ok" if success else "failed"
            finding_count = len(result.get("finding_titles") or [])
            on_progress(f"RESULT::investigation: {tool} {outcome}; {finding_count} finding title(s)")

    after_nodes = _current_nodes(engagement_id)
    after_evidence_ids = {oid for node in after_nodes for oid in node.observation_ids}
    evidence_ids = sorted(after_evidence_ids - before_evidence_ids)
    stopped_reason = "completed" if success else "one_or_more_tools_failed"
    return CapabilityResult(
        engagement_id=engagement_id, run_id=run_id, opportunity_id=opportunity_id,
        capability=kind, success=success,
        changed=len({n.id for n in after_nodes} - before_ids) + len(evidence_ids),
        stopped_reason=stopped_reason,
        evidence_ids=evidence_ids, details={"results": results},
    )
