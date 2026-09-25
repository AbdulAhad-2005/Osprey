"""Multi-factor prioritization — plans/harness/06-prioritization-engine.md.

Done criterion: a synthetic scenario where the interesting lead is a low-
count-but-high-centrality item outranks a high-count-but-boring area, and a
downstream phase unlocks on a real priority score crossing a threshold, not a
finding-count trigger (the mechanism plans/harness/06 Step 4 retired).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from osprey.schemas.observation import Observation, ObservationType
from osprey.services import priority
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_decay_is_1_at_zero_age_and_half_at_one_half_life():
    now = datetime.now(timezone.utc)
    assert priority._decay(now, None, 24.0, now) == 1.0
    half_life_ago = now - timedelta(hours=24)
    got = priority._decay(half_life_ago, None, 24.0, now)
    assert abs(got - 0.5) < 1e-6


def test_decay_falls_toward_zero_as_item_goes_stale():
    now = datetime.now(timezone.utc)
    stale = now - timedelta(hours=24 * 30)
    assert priority._decay(stale, None, 24.0, now) < 0.001


def test_config_merges_over_defaults_without_dropping_unlisted_keys():
    cfg = priority.load_priority_config()
    assert "objective_relevance" in cfg["weights"]
    assert cfg["phase_thresholds"]["vuln"] > 0
    assert "port" in cfg["observation_types"]


def test_unseeded_observation_type_falls_back_to_default_not_keyerror():
    cfg = priority.load_priority_config()
    priors = priority._obs_type_priors(cfg, "js_endpoint")
    assert priors == (cfg.get("observation_types") or {}).get("js_endpoint", cfg["default_observation_type"])


def test_score_observation_is_deterministic_given_same_inputs():
    eid = _make_engagement(f"priority-det-{_eid()}.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.PORT, target="priority-det.test",
                    source_tool="naabu_port_scan", details={"port": "443"}),
    )
    ctx = priority.build_context(eid)
    s1 = priority.score_observation(obs, ctx)
    s2 = priority.score_observation(obs, ctx)
    assert s1.total == s2.total
    assert s1.item_id == obs.id
    assert s1.item_kind == "observation"


def test_low_count_high_centrality_outranks_high_count_boring_area():
    """The plan's own done criterion: a single high-centrality lead should
    rank above many low-centrality 'boring' facts — priority is not a
    popularity count. Both sides are graph-ingested (as real tool output
    always is) so the only real difference is centrality, not whether the
    graph has seen them yet."""
    from osprey.schemas.engagement_graph import AssetType

    apex = f"priority-centrality-{_eid()}.test"
    eid = _make_engagement(apex)
    store = get_observation_store()
    graph = get_engagement_graph()

    # Boring area: 20 isolated technology observations — each touches the
    # graph (one host node, one distinct tech node, one edge) but stays a
    # single-edge leaf, real low centrality, not "never processed".
    for i in range(20):
        obs = store.record(Observation(
            engagement_id=eid, type=ObservationType.TECHNOLOGY, target=f"boring{i}.{apex}",
            source_tool="wappalyzer_scan", details={"name": f"lib{i}", "hostname": f"boring{i}.{apex}"},
        ))
        graph.ingest_observation(obs)

    # Interesting lead: ONE port observation whose host ends up with real
    # graph degree from several operator-linked siblings.
    hot_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.PORT, target=f"hot.{apex}",
        source_tool="naabu_port_scan", details={"port": "443", "hostname": f"hot.{apex}"},
    ))
    graph.ingest_observation(hot_obs)
    for i in range(8):
        graph.operator_link(
            engagement_id=eid, source_type=AssetType.HOST, source_label=f"extra{i}.{apex}",
            target_type=AssetType.HOST, target_label=f"hot.{apex}", relationship="dns_sibling",
            source_tool="test",
        )

    ranked = priority.top_priorities(eid, kinds=("observation",), limit=50)
    ranked_ids = [r.item_id for r in ranked]
    hot_rank = ranked_ids.index(hot_obs.id)
    boring_ranks = [i for i, s in enumerate(ranked) if s.type_key == "technology"]
    assert boring_ranks, "boring observations should still be scored, just lower"
    assert hot_rank < min(boring_ranks), (
        f"expected the high-centrality lead to outrank every boring item; "
        f"hot_rank={hot_rank} boring_ranks={boring_ranks}"
    )


def test_phase_unlocks_on_priority_not_finding_count():
    """A single real scanner_signal is enough to cross the exploit threshold —
    matching the old trigger's 'one real vuln IS reason enough' spirit, now
    computed from a score instead of a hardcoded count-of-1."""
    eid = _make_engagement(f"priority-phase-{_eid()}.test")
    store = get_observation_store()
    store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="phase-gate.test",
        source_tool="nuclei_scan", details={"title": "CVE-2099-1234 match", "severity": "critical"},
    ))
    unlocked, reason = priority.should_unlock_phase(eid, "exploit")
    assert unlocked, reason


def test_phase_locked_when_nothing_scored():
    eid = _make_engagement(f"priority-empty-{_eid()}.test")
    unlocked, reason = priority.should_unlock_phase(eid, "vuln")
    assert not unlocked
    assert "0.00" in reason or "< threshold" in reason


def test_repetition_penalizes_already_run_tool_on_same_asset():
    from osprey.services.tool_coverage_store import get_tool_coverage_store

    eid = _make_engagement(f"priority-repeat-{_eid()}.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.PORT, target="repeat.priority.test",
                    source_tool="naabu_port_scan", details={"port": "22"}),
    )
    ctx_before = priority.build_context(eid)
    before = priority.score_observation(obs, ctx_before)

    coverage = get_tool_coverage_store()
    for _ in range(5):
        coverage.record(engagement_id=eid, tool_name="naabu_port_scan", asset="repeat.priority.test", success=True)

    ctx_after = priority.build_context(eid)
    after = priority.score_observation(obs, ctx_after)
    assert after.factors.repetition > before.factors.repetition
    assert after.total < before.total


def test_single_tool_critical_outranks_triple_corroborated_info_of_same_type():
    """The scoring blind spot a real operator flagged: without severity
    awareness, every scanner_signal scored the same potential_impact
    regardless of what the scanner actually claimed, so a single-tool
    CRITICAL hit could rank behind a three-tool-corroborated info-level one
    purely on evidence_strength (occurrence count). A critical finding must
    never get silently buried behind a boring-but-well-corroborated one."""
    apex = f"severity-priority-{_eid()}.test"
    eid = _make_engagement(apex)
    store = get_observation_store()

    critical_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"critical.{apex}",
        source_tool="nuclei_scan", details={"title": "unauthenticated RCE via deserialization", "claimed_severity": "critical"},
    ))
    # Same observation, corroborated by 2 more independent tools — occurrence_count=3.
    for tool in ("jaeles_vulnerability_scan", "nikto_scan"):
        store.record(Observation(
            engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"critical.{apex}",
            source_tool=tool, details={"title": "unauthenticated RCE via deserialization", "claimed_severity": "critical"},
        ))

    boring_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"boring.{apex}",
        source_tool="nuclei_scan", details={"title": "missing security header", "claimed_severity": "info"},
    ))
    for tool in ("jaeles_vulnerability_scan", "nikto_scan"):
        store.record(Observation(
            engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"boring.{apex}",
            source_tool=tool, details={"title": "missing security header", "claimed_severity": "info"},
        ))

    ranked = priority.top_priorities(eid, kinds=("observation",), limit=10)
    ids = [r.item_id for r in ranked]
    assert ids.index(critical_obs.id) < ids.index(boring_obs.id)


def test_single_tool_critical_outranks_even_a_more_corroborated_unrated_finding():
    """The specific case the operator described: ONE tool reporting critical
    vs THREE tools reporting something with no severity info at all (a type
    whose flat per-type prior would otherwise dominate). Critical must still
    win — potential_impact from a real severity claim outweighs the
    evidence_strength gap from corroboration count."""
    apex = f"severity-priority-single-{_eid()}.test"
    eid = _make_engagement(apex)
    store = get_observation_store()

    critical_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"critical.{apex}",
        source_tool="nuclei_scan", details={"title": "SQL injection confirmed", "claimed_severity": "critical"},
    ))

    low_obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"unrated.{apex}",
        source_tool="nuclei_scan", details={"title": "generic banner match"},
    ))
    for tool in ("jaeles_vulnerability_scan", "nikto_scan"):
        store.record(Observation(
            engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=f"unrated.{apex}",
            source_tool=tool, details={"title": "generic banner match"},
        ))

    ranked = priority.top_priorities(eid, kinds=("observation",), limit=10)
    ids = [r.item_id for r in ranked]
    assert ids.index(critical_obs.id) < ids.index(low_obs.id)


def test_severity_absent_falls_back_to_type_prior_not_zero():
    """A port/technology observation has no severity concept at all — must
    still score a sensible non-zero impact from its type prior, not be
    treated as 'info' just because it has no claimed_severity key."""
    eid = _make_engagement(f"severity-fallback-{_eid()}.test")
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="fallback.test",
        source_tool="naabu_port_scan", details={"port": "443"},
    ))
    ctx = priority.build_context(eid)
    score = priority.score_observation(obs, ctx)
    cfg = priority.load_priority_config()
    assert score.factors.potential_impact == cfg["observation_types"]["port"]["impact"]


def test_asset_impact_is_keyed_on_asset_type_not_confidence():
    """The scoring blind spot's sibling on the asset side: potential_impact
    used to be `0.6 if confidence == "likely" else 0.4` — blind to WHAT the
    asset is, so a discovered CREDENTIAL node scored identical impact to a
    plain PORT node at the same confidence tier. Impact must come from
    asset_type (the same table score_observation uses), not confidence —
    confidence already has its own axis (evidence_strength)."""
    from osprey.schemas.engagement_graph import AssetNode, AssetType

    cfg = priority.load_priority_config()
    ctx = priority.PriorityContext(engagement_id="x")

    credential_node = AssetNode(id="credential:leaked-pw", asset_type=AssetType.CREDENTIAL, label="leaked-pw", confidence="likely")
    port_node = AssetNode(id="port:80", asset_type=AssetType.PORT, label="80", confidence="likely")

    cred_score = priority.score_asset(credential_node, ctx)
    port_score = priority.score_asset(port_node, ctx)

    assert cred_score.factors.potential_impact == cfg["observation_types"]["credential"]["impact"]
    assert port_score.factors.potential_impact == cfg["observation_types"]["port"]["impact"]
    assert cred_score.factors.potential_impact > port_score.factors.potential_impact


def test_asset_impact_no_longer_depends_on_confidence_tier():
    """Same asset_type, different confidence — impact must be identical (it's
    a property of what the asset IS, not how sure we are it exists); only
    evidence_strength should move with confidence/source-tool-count."""
    from osprey.schemas.engagement_graph import AssetNode, AssetType

    ctx = priority.PriorityContext(engagement_id="x")
    likely_node = AssetNode(id="host:a", asset_type=AssetType.HOST, label="a.test", confidence="likely")
    hypothesis_node = AssetNode(id="host:b", asset_type=AssetType.HOST, label="b.test", confidence="hypothesis")

    assert priority.score_asset(likely_node, ctx).factors.potential_impact == priority.score_asset(hypothesis_node, ctx).factors.potential_impact
