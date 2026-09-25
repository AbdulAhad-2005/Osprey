"""Surface Expansion Engine — one deterministic BFS pass. Mocks the graph and
execute_tool_request to test the trigger/delta logic in isolation (no DB, no
network), following this session's established pattern.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from osprey.schemas.engagement_graph import AssetType
from osprey.services.surface_expansion import run_expansion_pass


def _run(coro):
    return asyncio.run(coro)


def _node(asset_type, label, metadata=None):
    n = MagicMock()
    n.id = f"{asset_type.value}:{label}"
    n.asset_type = asset_type
    n.label = label
    n.metadata = metadata or {}
    return n


def _engagement_store(target: str):
    """Mock get_engagement_store() so _owned_apexes() has a real target_label —
    without this, engagement.target is None, owned_apexes is {""}, and every
    SUBDOMAIN node is (correctly, but not what the test wants) classified as
    third-party/external and excluded from the live-host pool entirely."""
    engagement = MagicMock()
    engagement.target = target
    store = MagicMock()
    store.get.return_value = engagement
    return store


def test_no_op_when_no_frontier():
    graph = MagicMock()
    graph.list_nodes.return_value = []
    graph.list_edges.return_value = []
    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        assert delta.frontier_processed == 0
        mock_exec.assert_not_awaited()


def test_unexpanded_domain_triggers_passive_discovery_dispatch():
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    graph = MagicMock()
    # before/after node+edge snapshots identical except we don't care about delta count here
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN
        else []
    )
    graph.list_edges.return_value = []
    graph.ensure_node.return_value = None

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        assert delta.frontier_processed == 1
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert {"subfinder_scan", "crt_sh_query", "gau_discovery", "domain_hunter"} <= called_tools
        # every call must be pinned to the engagement, not relying on ambient state
        assert all(c.args[0].engagement_id == "e1" for c in mock_exec.await_args_list)


def test_already_expanded_nodes_skipped():
    domain_node = _node(AssetType.DOMAIN, "example.com", {"expanded": True})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        assert delta.frontier_processed == 0
        mock_exec.assert_not_awaited()


def test_one_tool_failure_does_not_abort_the_pass():
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN else []
    )
    graph.list_edges.return_value = []

    async def _flaky(request):
        if request.tool_name == "subfinder_scan":
            raise RuntimeError("kali-tools unreachable")
        return None

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", side_effect=_flaky) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        # one tool raised, the rest of the domain-discovery set still got called
        called_tools = {c.args[0].tool_name for c in mock_exec.call_args_list}
        assert "crt_sh_query" in called_tools
        assert delta.frontier_processed == 1


def test_origin_candidate_host_enters_live_expansion():
    origin_node = _node(AssetType.HOST, "1.2.3.4", {"role": "origin_candidate"})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [origin_node] if kw.get("asset_type") == AssetType.HOST else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "naabu_port_scan" in called_tools
        assert delta.frontier_processed == 1


def test_no_engagement_id_is_a_safe_noop():
    delta = _run(run_expansion_pass(engagement_id="", run_id="r1"))
    assert delta.frontier_processed == 0


def test_amass_included_in_domain_discovery_dispatch():
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "amass_scan" in called_tools


def test_domain_only_tools_run_for_domain_but_not_subdomain():
    """whois/theharvester are apex-level — must fire once for a DOMAIN node,
    never per SUBDOMAIN (that would repeat the identical call many times)."""
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    subdomain_node = _node(AssetType.SUBDOMAIN, "www.example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN
        else [subdomain_node] if kw.get("asset_type") == AssetType.SUBDOMAIN
        else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        whois_calls = [c for c in mock_exec.await_args_list if c.args[0].tool_name == "whois_lookup"]
        harvester_calls = [c for c in mock_exec.await_args_list if c.args[0].tool_name == "theharvester"]
        assert len(whois_calls) == 1
        assert len(harvester_calls) == 1
        assert whois_calls[0].args[0].params == {"target": "example.com"}


def test_small_netblock_expands_into_subnet_sibling_ip_nodes():
    netblock_finding = MagicMock()
    netblock_finding.metadata = {"cidr": "10.0.0.0/30"}  # 4 addresses, 2 usable hosts

    graph = MagicMock()
    graph.list_nodes.return_value = []
    graph.list_edges.return_value = []
    created_ips = []

    def _ensure_node(*, engagement_id, asset_type, label, metadata=None):
        if asset_type == AssetType.IP and (metadata or {}).get("role") == "subnet_sibling":
            created_ips.append(label)
        return MagicMock()

    graph.ensure_node.side_effect = _ensure_node

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock), \
         patch("osprey.services.findings_store.get_findings_store") as mock_store:
        mock_store.return_value.list.return_value = [netblock_finding]
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))

    assert set(created_ips) == {"10.0.0.1", "10.0.0.2"}


def test_large_netblock_never_auto_swept():
    netblock_finding = MagicMock()
    netblock_finding.metadata = {"cidr": "10.0.0.0/16"}  # 65534 usable hosts — must not sweep

    graph = MagicMock()
    graph.list_nodes.return_value = []
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock), \
         patch("osprey.services.findings_store.get_findings_store") as mock_store:
        mock_store.return_value.list.return_value = [netblock_finding]
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))

    subnet_sibling_calls = [
        c for c in graph.ensure_node.call_args_list
        if c.kwargs.get("metadata", {}).get("role") == "subnet_sibling"
    ]
    assert subnet_sibling_calls == []


def test_low_confidence_origin_candidate_is_held_back_not_scanned():
    origin_node = _node(AssetType.HOST, "62.149.128.42", {"role": "origin_candidate", "confidence": 0.4})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [origin_node] if kw.get("asset_type") == AssetType.HOST else []
    )
    graph.list_edges.return_value = []
    progress_lines: list[str] = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1", on_progress=progress_lines.append))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "naabu_port_scan" not in called_tools
        assert delta.frontier_processed == 0
        assert any("held back" in line and "62.149.128.42" in line for line in progress_lines)


def test_include_low_confidence_override_scans_it_anyway():
    origin_node = _node(AssetType.HOST, "62.149.128.42", {"role": "origin_candidate", "confidence": 0.4})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [origin_node] if kw.get("asset_type") == AssetType.HOST else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        delta = _run(run_expansion_pass(engagement_id="e1", run_id="r1", min_origin_confidence=0.0))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "naabu_port_scan" in called_tools
        assert delta.frontier_processed == 1


def test_non_resolving_host_skips_the_live_host_battery():
    """The actual regression this guards: wordlist-guessed subdomains that
    never resolve (dead certs, decommissioned hosts, literal "*.example.com"
    wildcard strings misread as a real hostname) were getting the full
    port-scan/tech/WAF/CDN/vuln battery run against them anyway — every tool
    correctly reporting "nothing here" for something DNS already can't find,
    flooding results with noise and wasting real time. A cheap resolution
    check must skip the battery entirely instead."""
    dead_node = _node(AssetType.SUBDOMAIN, "ghost.example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [dead_node] if kw.get("asset_type") == AssetType.SUBDOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.surface_expansion.resolve_host_ip", return_value=None), \
         patch("osprey.services.engagement_store.get_engagement_store", return_value=_engagement_store("example.com")), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "naabu_port_scan" not in called_tools
        assert "httpx_probe" not in called_tools
        assert "wafw00f_scan" not in called_tools
        # it's still tracked (not silently dropped) even though the battery is
        # skipped — a dead-attempt marker is recorded so repeated dead passes
        # eventually stop retrying (_DEAD_KILL_PASSES) instead of the node just
        # vanishing from view. (frontier_processed only counts domain-stage +
        # LIVE hosts, so it's correctly 0 here — not the right signal for "was
        # this dead node processed at all".)
        dead_tracking_calls = [
            c for c in graph.ensure_node.call_args_list
            if c.kwargs.get("label") == "ghost.example.com"
        ]
        assert dead_tracking_calls


def test_resolving_host_still_gets_the_full_battery():
    live_node = _node(AssetType.SUBDOMAIN, "real.example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [live_node] if kw.get("asset_type") == AssetType.SUBDOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.surface_expansion.resolve_host_ip", return_value="203.0.113.5"), \
         patch("osprey.services.engagement_store.get_engagement_store", return_value=_engagement_store("example.com")), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "naabu_port_scan" in called_tools
        assert "httpx_probe" in called_tools


def test_web_depth_gated_off_by_default_even_on_live_web_host():
    """web_depth (feroxbuster/js_recon/well_known_probe) must never fire unless
    phases.web_depth is explicitly enabled — an "enumerate subs/IPs/ports" ask
    must not get content discovery as an unconditional breadth-pass side
    effect (config/expansion.yaml's `phases.web_depth: false` default)."""
    live_node = _node(AssetType.SUBDOMAIN, "real.example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [live_node] if kw.get("asset_type") == AssetType.SUBDOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.surface_expansion.resolve_host_ip", return_value="203.0.113.5"), \
         patch("osprey.services.surface_expansion._host_is_live_web", return_value=True), \
         patch("osprey.services.engagement_store.get_engagement_store", return_value=_engagement_store("example.com")), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "feroxbuster_scan" not in called_tools
        assert "js_recon" not in called_tools
        assert "well_known_probe" not in called_tools
        # the gate is scoped to web_depth only — the rest of host_expansion still runs
        assert "naabu_port_scan" in called_tools


def test_web_depth_runs_when_phase_enabled():
    live_node = _node(AssetType.SUBDOMAIN, "real.example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [live_node] if kw.get("asset_type") == AssetType.SUBDOMAIN else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.surface_expansion.resolve_host_ip", return_value="203.0.113.5"), \
         patch("osprey.services.surface_expansion._host_is_live_web", return_value=True), \
         patch("osprey.services.surface_expansion._phase_enabled", side_effect=lambda name: name == "web_depth"), \
         patch("osprey.services.engagement_store.get_engagement_store", return_value=_engagement_store("example.com")), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec:
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert "feroxbuster_scan" in called_tools
        assert "well_known_probe" in called_tools


def test_hung_tool_does_not_block_the_pass():
    """A tool that never returns (crt.sh hanging/502-looping in practice) must
    not block the pass forever — the per-task wait_for ceiling must actually
    fire. Every dispatched tool hangs here; if the ceiling didn't work, the
    outer 5s wait_for around the whole pass would raise TimeoutError."""
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN else []
    )
    graph.list_edges.return_value = []

    async def _always_hangs(request):
        await asyncio.sleep(3600)

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.surface_expansion._DOMAIN_DISCOVERY_TIMEOUT", 0.05), \
         patch("osprey.services.surface_expansion._DOMAIN_ONLY_TIMEOUT", 0.05), \
         patch("osprey.services.tool_execution.execute_tool_request", side_effect=_always_hangs):
        delta = _run(asyncio.wait_for(run_expansion_pass(engagement_id="e1", run_id="r1"), timeout=5))
        assert delta.frontier_processed == 1


def test_on_progress_reports_in_flight_tool_names():
    domain_node = _node(AssetType.DOMAIN, "example.com", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [domain_node] if kw.get("asset_type") == AssetType.DOMAIN else []
    )
    graph.list_edges.return_value = []
    progress_lines: list[str] = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock):
        _run(run_expansion_pass(engagement_id="e1", run_id="r1", on_progress=progress_lines.append))

    assert progress_lines, "on_progress must be called at least once"
    assert any("subfinder_scan" in line or "crt_sh_query" in line for line in progress_lines)


def test_asn_enum_dispatched_for_unchecked_ips():
    ip_node = _node(AssetType.IP, "5.6.7.8", {})
    graph = MagicMock()
    graph.list_nodes.side_effect = lambda **kw: (
        [ip_node] if kw.get("asset_type") == AssetType.IP else []
    )
    graph.list_edges.return_value = []

    with patch("osprey.services.surface_expansion.get_engagement_graph", return_value=graph), \
         patch("osprey.services.tool_execution.execute_tool_request", new_callable=AsyncMock) as mock_exec, \
         patch("osprey.services.findings_store.get_findings_store") as mock_store:
        mock_store.return_value.list.return_value = []
        _run(run_expansion_pass(engagement_id="e1", run_id="r1"))
        called_tools = {c.args[0].tool_name for c in mock_exec.await_args_list}
        assert {"dnsx_reverse", "asn_enum"} <= called_tools
