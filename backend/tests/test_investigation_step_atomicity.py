"""End-to-end proof that list_step/execute_capability never batch more than
one real tool call behind a single opportunity — the actual architectural
property this module exists to guarantee. Exercises real wiring (graph,
priority, tool_coverage, findings) that the narrower unit tests in
test_investigation_capabilities.py don't reach.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services import investigation_capabilities
from osprey.services.engagement_graph import get_engagement_graph


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_list_step_seeded_domain_yields_only_single_tool_opportunities():
    eid = _make_engagement("atomic-step.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-step.test",
    )

    step = investigation_capabilities.list_step(eid)

    assert step.opportunities, "expected at least one opportunity for a fresh domain seed"
    for opp in step.opportunities:
        if opp.capability.value in {"detect_anomalies", "refresh_exploit_candidates"}:
            continue  # analytical kinds legitimately carry no tool
        assert opp.tool, f"opportunity {opp.id} ({opp.capability}) has no tool — cannot be atomic"
        assert isinstance(opp.params, dict)


def test_execute_capability_runs_exactly_one_tool_call():
    """The core regression: executing ANY opportunity must invoke the tool
    execution kernel exactly once, never several tools via asyncio.gather."""
    eid = _make_engagement("atomic-execute.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-execute.test",
    )
    step = investigation_capabilities.list_step(eid)
    tool_opps = [o for o in step.opportunities if o.tool]
    assert tool_opps, "need at least one tool-backed opportunity to test"
    opp = tool_opps[0]

    call_count = 0

    async def _fake_execute_tool_request(request):
        nonlocal call_count
        call_count += 1
        return ToolExecutionResponse(tool_name=request.tool_name, success=True, stdout="ok")

    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new=AsyncMock(side_effect=_fake_execute_tool_request),
    ):
        result = asyncio.run(investigation_capabilities.execute_capability(
            engagement_id=eid, run_id="", opportunity_id=opp.id, capability=opp.capability.value,
            subject_ids=[s.asset_id for s in opp.subjects], tool=opp.tool, params=dict(opp.params),
            additional_args=opp.additional_args,
        ))

    assert call_count == 1, f"expected exactly one tool execution, got {call_count}"
    assert result.details["results"], "expected exactly one result entry"
    assert len(result.details["results"]) == 1


def test_execute_capability_without_tool_and_non_analytical_kind_fails_cleanly():
    """An opportunity kind that requires a tool but received none (a caller
    bug, not a legitimate analytical opportunity) must fail loudly, never
    silently no-op or fall back to running something unrelated."""
    eid = _make_engagement("atomic-missing-tool.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-missing-tool.test",
    )
    result = asyncio.run(investigation_capabilities.execute_capability(
        engagement_id=eid, run_id="", opportunity_id="opp_fake", capability="probe_live_assets",
        subject_ids=[], tool="", params={},
    ))
    assert result.success is False
    assert result.stopped_reason == "capability_unavailable"


def test_low_confidence_origin_candidate_is_held_back_from_probing():
    """Regression for a gap found auditing run_expansion_pass (Plan 18): a
    low-confidence origin-IP guess must not be port-scanned as if it were a
    confirmed live host — 'merely finding an IP near the target is not
    origin attribution.'"""
    eid = _make_engagement("atomic-origin-holdback.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.IP, label="198.51.100.9",
        metadata={"role": "origin_candidate", "confidence": 0.2},
    )

    step = investigation_capabilities.list_step(eid)

    probe_opps = [o for o in step.opportunities if o.capability.value == "probe_live_assets"]
    assert not probe_opps, "a low-confidence origin candidate must not get PROBE_LIVE_ASSETS opportunities"


def test_confirmed_origin_candidate_is_probed():
    eid = _make_engagement("atomic-origin-confirmed.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.IP, label="198.51.100.10",
        metadata={"role": "origin_candidate", "confidence": 0.9},
    )

    step = investigation_capabilities.list_step(eid)

    probe_opps = [o for o in step.opportunities if o.capability.value == "probe_live_assets"]
    assert probe_opps, "a high-confidence origin candidate must still get PROBE_LIVE_ASSETS opportunities"


def test_small_netblock_yields_sweep_opportunity_and_execution_creates_ip_nodes():
    """Regression for a gap found auditing run_expansion_pass (Plan 18): a
    small asn_prefix CIDR must expand into individual subnet_sibling IP
    nodes so they flow into PROBE_LIVE_ASSETS like any other IP."""
    from osprey.services.observation_store import get_observation_store
    from osprey.schemas.observation import Observation, ObservationType

    eid = _make_engagement("atomic-netblock-sweep.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-netblock-sweep.test",
    )
    # asn_enum records each announced prefix as an ASN observation with
    # details['cidr'] — the sweep reads these directly since Phase 2 (no finding).
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.ASN, target="atomic-netblock-sweep.test",
        source_tool="asn_enum", tags=["netblock", "asn", "asn_prefix"],
        details={"cidr": "10.0.0.0/30", "asn": "AS65000", "role": "netblock"},
    ))

    step = investigation_capabilities.list_step(eid)
    sweep_opps = [o for o in step.opportunities if o.capability.value == "sweep_netblock"]
    assert sweep_opps, "expected a SWEEP_NETBLOCK opportunity for the unswept small CIDR"
    opp = sweep_opps[0]
    assert opp.evidence.get("cidr") == "10.0.0.0/30"

    result = asyncio.run(investigation_capabilities.execute_capability(
        engagement_id=eid, run_id="", opportunity_id=opp.id, capability=opp.capability.value,
        subject_ids=[s.asset_id for s in opp.subjects], capability_input=dict(opp.evidence),
    ))
    assert result.success is True
    assert result.details["results"][0]["hosts_created"] == 2  # /30 has 2 usable hosts

    created_ips = {
        n.label for n in get_engagement_graph().list_nodes(engagement_id=eid, asset_type=AssetType.IP, limit=50)
        if n.metadata.get("role") == "subnet_sibling"
    }
    assert created_ips == {"10.0.0.1", "10.0.0.2"}

    # Re-listing must not offer the same CIDR again — it's now swept.
    step_after = investigation_capabilities.list_step(eid)
    assert not [o for o in step_after.opportunities if o.capability.value == "sweep_netblock"]


def test_large_netblock_never_auto_swept():
    """A /16+ CIDR must never auto-sweep — a mechanical-DoS-risk guard the
    old run_expansion_pass enforced via _MAX_AUTO_SWEEP_ADDRESSES; ported to
    the atomic model's SWEEP_NETBLOCK opportunity generation."""
    from osprey.services.observation_store import get_observation_store
    from osprey.schemas.observation import Observation, ObservationType

    eid = _make_engagement("atomic-netblock-too-large.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-netblock-too-large.test",
    )
    # asn_enum records the prefix as an ASN observation (details.cidr); the sweep
    # reads observations since Phase 2 — a /16 must be recorded but never swept.
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.ASN, target="atomic-netblock-too-large.test",
        source_tool="asn_enum", tags=["netblock", "asn", "asn_prefix"],
        details={"cidr": "10.0.0.0/16", "asn": "AS65000", "role": "netblock"},
    ))

    step = investigation_capabilities.list_step(eid)
    sweep_opps = [o for o in step.opportunities if o.capability.value == "sweep_netblock"]
    assert not sweep_opps, "a /16 netblock (65534 usable hosts) must never be auto-swept"


def test_breach_intel_tools_only_offered_when_keyed(monkeypatch):
    """Regression for a gap found auditing run_expansion_pass (Plan 18): the
    HARVEST_CONTACTS opportunity must offer env-keyed breach/passive-intel
    tools only when their key is actually configured — AGENTS.md's 'when
    keyed' guidance made mechanical, not an LLM judgment call."""
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    monkeypatch.delenv("INTELX_API_KEY", raising=False)
    monkeypatch.delenv("RESECURITY_API_KEY", raising=False)

    eid = _make_engagement("atomic-breach-intel-keyed.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-breach-intel-keyed.test",
    )

    step = investigation_capabilities.list_step(eid)
    harvest_tools = {o.tool for o in step.opportunities if o.capability.value == "harvest_contacts"}
    assert "theharvester" in harvest_tools
    assert "web_contact_harvest" in harvest_tools
    # Whichever breach tool config/breach_intel_tools.yaml maps SHODAN_API_KEY
    # to should appear; nothing gated behind an unset key should.
    assert not ({"intelx_scan", "resecurity_scan"} & harvest_tools)


def test_tech_dispatch_targets_each_matched_host_not_only_the_seed():
    """The actual bug this fixes (Plan 18 Workstream B): before, every
    tech_dispatch-triggered tool ran against the engagement seed only,
    regardless of which host actually matched the rule (traced end to end:
    run_dispatch_step's params={} -> extract_target -> seed fallback). Two
    distinct WordPress hosts must now yield two wpscan_analyze opportunities
    targeting the two real hosts, never the same seed-only dispatch twice."""
    from osprey.services.observation_store import get_observation_store
    from osprey.schemas.observation import Observation, ObservationType

    eid = _make_engagement("atomic-per-host-dispatch.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-per-host-dispatch.test",
    )

    for host in ("blog.atomic-per-host-dispatch.test", "shop.atomic-per-host-dispatch.test"):
        # A TECHNOLOGY observation only exists after a host has been resolved/
        # probed into the graph (httpx_probe/whatweb/tech_stack_analyze) — seed
        # that realistic prior state. Since Phase 2, dispatch keys off this
        # observation directly, no finding needed.
        get_engagement_graph().ensure_node(
            engagement_id=eid, asset_type=AssetType.SUBDOMAIN, label=host,
        )
        get_observation_store().record(Observation(
            engagement_id=eid, type=ObservationType.TECHNOLOGY, target=host,
            source_tool="whatweb_scan", details={"technology": "WordPress 6.4"},
        ))

    step = investigation_capabilities.list_step(eid)

    wpscan_opps = [o for o in step.opportunities if o.tool == "wpscan_analyze"]
    targeted_hosts = {o.params.get("target") for o in wpscan_opps}
    assert targeted_hosts == {
        "blog.atomic-per-host-dispatch.test", "shop.atomic-per-host-dispatch.test",
    }, f"expected one wpscan opportunity per real host, got targets={targeted_hosts}"


def test_osint_enrichment_dispatch_uses_matched_value_not_a_hostname():
    """A holehe/phoneinfoga-style OSINT enrichment rule needs the matched
    finding's actual value (an email string) as its dispatch param — not a
    'target' hostname, and not the engagement seed either."""
    from osprey.services.observation_store import get_observation_store
    from osprey.schemas.observation import Observation, ObservationType

    eid = _make_engagement("atomic-osint-enrich.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-osint-enrich.test",
    )
    # An EMAIL observation carrying the address as its title — the osint_email_found
    # rule (params_from: {email: title}) pulls that value into the holehe param.
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.EMAIL, target="atomic-osint-enrich.test",
        source_tool="theharvester",
        details={"title": "contact.person@atomic-osint-enrich.test"},
    ))

    step = investigation_capabilities.list_step(eid)

    holehe_opps = [o for o in step.opportunities if o.tool == "holehe"]
    assert holehe_opps, "expected a holehe opportunity for the discovered email"
    assert holehe_opps[0].params.get("email") == "contact.person@atomic-osint-enrich.test"
    assert "target" not in holehe_opps[0].params


def test_discover_related_domains_carries_a_bounded_timeout_end_to_end():
    """Regression for a real production hang: a plain dnsenum_scan call with
    no per-stage timeout inherited the execution kernel's generic 900s
    default, tripled by its own retry-on-timeout behavior — ~45 minutes for
    one domain-level OSINT lookup. Every DISCOVER_RELATED_DOMAINS opportunity
    must carry a real, short timeout, and execute_capability must actually
    pass it to the execution kernel, not just compute it and drop it."""
    eid = _make_engagement("atomic-timeout-bound.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="atomic-timeout-bound.test",
    )

    step = investigation_capabilities.list_step(eid)
    discover_opps = [o for o in step.opportunities if o.capability.value == "discover_related_domains"]
    assert discover_opps, "expected at least one DISCOVER_RELATED_DOMAINS opportunity"
    for opp in discover_opps:
        assert 0 < opp.timeout <= 120, f"{opp.tool} opportunity has no short bound: timeout={opp.timeout}"

    opp = discover_opps[0]
    captured_requests = []

    async def _fake_execute_tool_request(request):
        captured_requests.append(request)
        return ToolExecutionResponse(tool_name=request.tool_name, success=True, stdout="ok")

    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new=AsyncMock(side_effect=_fake_execute_tool_request),
    ):
        asyncio.run(investigation_capabilities.execute_capability(
            engagement_id=eid, run_id="", opportunity_id=opp.id, capability=opp.capability.value,
            subject_ids=[s.asset_id for s in opp.subjects], tool=opp.tool, params=dict(opp.params),
            additional_args=opp.additional_args, timeout=opp.timeout,
        ))

    assert captured_requests[0].timeout == opp.timeout != 900
