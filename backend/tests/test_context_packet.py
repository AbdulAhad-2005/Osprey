"""The context packet — plans/harness/07-context-packet.md.

Done criteria this covers: every declared section is present and populated
from real store data (not fabricated), and the packet is a pure function of
the world model — rebuilding it after more evidence lands shows the new
evidence, proving nothing here depends on conversation history.
"""

from __future__ import annotations

import uuid

from osprey.schemas.attack_path import AttackPathStep, AttackPathStepKind
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import attack_path_store, hypothesis_store, question_store
from osprey.services.context_packet import build_context_packet
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.evidence_store import get_evidence_store
from osprey.services.observation_store import get_observation_store
from osprey.services.tool_coverage_store import get_tool_coverage_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_no_engagement_returns_a_clear_message_not_a_crash():
    assert "no engagement bound" in build_context_packet("").lower()


def test_unknown_engagement_does_not_crash():
    packet = build_context_packet("does-not-exist-" + _eid())
    assert "CONTEXT PACKET" in packet


def test_every_declared_section_is_present():
    eid = _make_engagement(f"packet-sections-{_eid()}.test")
    packet = build_context_packet(eid)
    for heading in (
        "OBJECTIVE + SCOPE", "WORLD MODEL SUMMARY", "COVERAGE", "TOP PRIORITIES",
        "OPEN QUESTIONS", "ACTIVE HYPOTHESES", "ACTIVE ATTACK PATHS",
        "RECENT EVIDENCE", "TOOLS ALREADY RUN", "CONSTRAINTS",
    ):
        assert f"## {heading}" in packet, f"missing section: {heading}"


def test_objective_and_scope_shows_the_real_target():
    apex = f"packet-target-{_eid()}.test"
    eid = _make_engagement(apex)
    packet = build_context_packet(eid)
    assert apex in packet


def test_world_model_summary_reflects_discovered_assets():
    eid = _make_engagement(f"packet-assets-{_eid()}.test")
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="packet-host.test",
        details={"hostname": "packet-host.test", "port": "22"},
    ))
    packet = build_context_packet(eid)
    assert "packet-host.test" in packet
    assert "host (1)" in packet or "port (1)" in packet


def test_coverage_lists_hosts_missing_port_evidence():
    eid = _make_engagement(f"packet-coverage-{_eid()}.test")
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="uncovered.test",
        details={"hostname": "uncovered.test"},
    ))
    packet = build_context_packet(eid)
    assert "uncovered.test" in packet


def test_top_priorities_reflects_a_real_scanner_signal():
    eid = _make_engagement(f"packet-priority-{_eid()}.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="hot.packet-priority.test",
        source_tool="nuclei_scan", details={"title": "CVE-2099-4444 match"},
    ))
    packet = build_context_packet(eid)
    assert "scanner_signal" in packet


def test_open_questions_and_active_hypotheses_appear():
    eid = _make_engagement(f"packet-reasoning-{_eid()}.test")
    q = question_store.raise_question(eid, text="is auth required on /admin?")
    h = hypothesis_store.raise_hypothesis(eid, statement="admin panel is exposed")
    packet = build_context_packet(eid)
    assert q.text in packet
    assert h.statement in packet


def test_active_attack_paths_show_status_and_last_step():
    eid = _make_engagement(f"packet-attackpath-{_eid()}.test")
    step = AttackPathStep(kind=AttackPathStepKind.OBSERVATION, ref_id="obs1", rationale="entry point found")
    attack_path_store.propose(eid, title="test chain", steps=[step])
    packet = build_context_packet(eid)
    assert "test chain" in packet
    assert "entry point found" in packet


def test_recent_evidence_lists_tool_runs_with_evidence_id():
    eid = _make_engagement(f"packet-evidence-{_eid()}.test")
    ev = get_evidence_store().record(
        engagement_id=eid, tool_name="nmap_service_scan", target="evidence.test",
        command="nmap -sV evidence.test", exit_code=0, duration_ms=100,
    )
    packet = build_context_packet(eid)
    assert "nmap_service_scan" in packet
    assert ev.id in packet


def test_tools_already_run_groups_by_asset():
    eid = _make_engagement(f"packet-coverage-tools-{_eid()}.test")
    get_tool_coverage_store().record(engagement_id=eid, tool_name="naabu_port_scan", asset="tools.test", success=True)
    packet = build_context_packet(eid)
    assert "naabu_port_scan" in packet
    assert "tools.test" in packet


def test_constraints_reflect_roe_blocks():
    eid = _make_engagement(f"packet-constraints-{_eid()}.test")
    from osprey.services.engagement_store import get_engagement_store

    store = get_engagement_store()
    eng = store.get(eid)
    eng.rules_of_engagement.allow_exploitation = False
    store.update(eng)
    packet = build_context_packet(eid)
    assert "exploitation=BLOCKED" in packet


def test_packet_is_pure_function_of_world_model_not_conversation_history():
    """The done criterion in spirit: rebuilding the packet from scratch (no
    conversation history passed anywhere) after new evidence lands shows the
    new evidence — nothing here can be 'lost' since it never lived in
    history to begin with."""
    eid = _make_engagement(f"packet-purity-{_eid()}.test")
    before = build_context_packet(eid)
    assert "jenkins" not in before.lower()

    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="purity.test",
        source_tool="nuclei_scan", details={"title": "Jenkins dashboard exposed"},
    ))
    after = build_context_packet(eid)
    assert "jenkins" in after.lower()
