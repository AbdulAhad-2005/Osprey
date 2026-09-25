"""CLI parity for plans/harness/03 (earned-finding pipeline) and 05 (world
model + attack paths + reasoning) — these commands didn't exist until this
sweep; before it, only an MCP client could reach file_finding/promote/world
model/attack paths/questions/hypotheses. Mocks at the APIClient boundary,
same convention as test_fp_cache_cli.py — the backend-side logic has its own
test suite (backend/tests/test_finding_pipeline.py, test_reasoning_endpoints.py).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from cli.commands.slash import (
    handle_attackpath,
    handle_context,
    handle_file,
    handle_hypothesis,
    handle_link,
    handle_observations,
    handle_priority,
    handle_promote,
    handle_question,
    handle_record,
    handle_skills,
    handle_world,
)


@pytest.fixture
def client():
    c = MagicMock()
    c.active_engagement_id = "eng1"
    return c


def test_observations_no_engagement_bound(capsys):
    c = MagicMock()
    c.active_engagement_id = None
    handle_observations([], c)
    c.list_observations.assert_not_called()
    assert "No engagement bound" in capsys.readouterr().out


def test_observations_lists_rows(client, capsys):
    client.list_observations.return_value = {
        "total": 1,
        "observations": [{"id": "o1", "type": "port", "target": "h", "source_tool": "nmap", "occurrence_count": 1, "details": {}}],
    }
    handle_observations(["port"], client)
    client.list_observations.assert_called_once_with("eng1", observation_type="port", target="", limit=200)
    assert "id=o1" in capsys.readouterr().out


def test_promote_reports_confidence_breakdown(client, capsys):
    client.promote_observations.return_value = {"total": 1, "findings": [{"confidence": "hypothesis"}]}
    handle_promote([], client)
    out = capsys.readouterr().out
    assert "Promoted 1 finding(s)" in out
    assert "hypothesis" in out


def test_file_requires_engagement():
    c = MagicMock()
    c.active_engagement_id = None
    handle_file(["url", "o1", "a", "title"], c)
    c.file_finding.assert_not_called()


def test_file_usage_with_too_few_args(client, capsys):
    handle_file(["url"], client)
    client.file_finding.assert_not_called()
    assert "Usage" in capsys.readouterr().out


def test_file_calls_client_with_parsed_fields(client, capsys):
    client.file_finding.return_value = {
        "finding": {"id": "f1", "finding_type": "url", "confidence": "hypothesis", "claim_severity": "none"},
        "suppressed": False,
    }
    handle_file(["url", "o1,o2", "a", "title", "here", "--severity", "high", "--evidence", "corroboration", "--evidence-tool", "nikto"], client)
    client.file_finding.assert_called_once_with(
        engagement_id="eng1", title="a title here", finding_type="url",
        observation_ids=["o1", "o2"], claim_severity="high", description="",
        evidence_records=[{"kind": "corroboration", "source_tool": "nikto", "detail": ""}],
        target="", tags=[],
    )
    assert "Filed finding id=f1" in capsys.readouterr().out


def test_file_reports_suppression(client, capsys):
    client.file_finding.return_value = {"finding": None, "suppressed": True, "suppressed_reason": "matches pattern p1"}
    handle_file(["url", "o1", "a", "title"], client)
    assert "Not filed" in capsys.readouterr().out


def test_world_assets_view(client, capsys):
    client.world_model_assets.return_value = {"assets": [{"id": "host:h", "confidence": "likely", "source_tools": ["nmap"]}]}
    handle_world(["assets"], client)
    out = capsys.readouterr().out
    assert "host:h" in out
    assert "view=assets count=1" in out


def test_world_related_requires_asset_id(client, capsys):
    handle_world(["related"], client)
    client.world_model_related.assert_not_called()
    assert "requires asset_id" in capsys.readouterr().out


def test_world_unknown_view(client, capsys):
    handle_world(["bogus"], client)
    assert "view must be one of" in capsys.readouterr().out


def test_attackpath_propose(client, capsys):
    client.propose_attack_path.return_value = {"id": "p1", "status": "hypothesized"}
    handle_attackpath(["propose", "my chain", "observation", "o1", "seed step"], client)
    client.propose_attack_path.assert_called_once_with(
        "eng1", title="my chain", steps=[{"kind": "observation", "ref_id": "o1", "rationale": "seed step"}],
    )
    assert "proposed" in capsys.readouterr().out.lower()


def test_attackpath_advance_with_status_and_step(client, capsys):
    client.advance_attack_path.return_value = {"id": "p1", "status": "validated", "steps": [1, 2]}
    handle_attackpath(["advance", "p1", "--status", "validated", "--step", "observation", "o2", "next hop"], client)
    client.advance_attack_path.assert_called_once_with(
        "p1", status="validated", finding_id="",
        step={"kind": "observation", "ref_id": "o2", "rationale": "next hop"},
    )
    assert "advanced" in capsys.readouterr().out.lower()


def test_attackpath_list_empty(client, capsys):
    client.list_attack_paths.return_value = {"attack_paths": []}
    handle_attackpath(["list"], client)
    assert "No active attack paths" in capsys.readouterr().out


def test_question_raise_and_list(client, capsys):
    client.raise_question.return_value = {"id": "q1", "text": "is this reachable?"}
    handle_question(["raise", "is", "this", "reachable?"], client)
    client.raise_question.assert_called_once_with("eng1", text="is this reachable?", related_asset_id="")
    assert "Question raised" in capsys.readouterr().out

    client.list_questions.return_value = {"questions": [{"id": "q1", "text": "is this reachable?"}]}
    handle_question(["list"], client)
    client.list_questions.assert_called_once_with("eng1", open_only=True)


def test_hypothesis_raise_and_evidence(client, capsys):
    client.raise_hypothesis.return_value = {"id": "h1", "statement": "exploitable"}
    handle_hypothesis(["raise", "exploitable", "o1", "o2"], client)
    client.raise_hypothesis.assert_called_once_with("eng1", statement="exploitable", supporting_observation_ids=["o1", "o2"])

    client.add_hypothesis_evidence.return_value = {"supporting_observation_ids": ["o1"], "contradicting_observation_ids": []}
    handle_hypothesis(["evidence", "h1", "o1", "true"], client)
    client.add_hypothesis_evidence.assert_called_once_with("h1", observation_id="o1", supports=True)


def test_priority_top_lists_ranked_items(client, capsys):
    client.top_priorities.return_value = {
        "items": [{"total": 3.21, "item_kind": "observation", "type_key": "port", "label": "hot.test", "target": "hot.test"}],
    }
    handle_priority([], client)
    client.top_priorities.assert_called_once_with("eng1", kinds="observation,asset,question,attack_path", limit=20)
    out = capsys.readouterr().out
    assert "3.21" in out
    assert "hot.test" in out


def test_priority_phase_reports_unlock_status(client, capsys):
    client.phase_priority.return_value = {"phase": "exploit", "unlocked": True, "gate_reason": "scanner_signal priority=2.5 >= threshold 2.20"}
    handle_priority(["phase", "exploit"], client)
    client.phase_priority.assert_called_once_with("eng1", "exploit")
    out = capsys.readouterr().out
    assert "UNLOCKED" in out
    assert "threshold" in out


def test_priority_requires_engagement():
    c = MagicMock()
    c.active_engagement_id = None
    handle_priority([], c)
    c.top_priorities.assert_not_called()


def test_context_prints_the_packet(client, capsys):
    client.get_context_packet.return_value = "CONTEXT PACKET — generated ...\n\n## OBJECTIVE + SCOPE\ntarget: example.com"
    handle_context([], client)
    client.get_context_packet.assert_called_once_with("eng1")
    out = capsys.readouterr().out
    assert "OBJECTIVE + SCOPE" in out
    assert "example.com" in out


def test_context_requires_engagement():
    c = MagicMock()
    c.active_engagement_id = None
    handle_context([], c)
    c.get_context_packet.assert_not_called()


def test_skills_bare_shows_router_index(client, capsys):
    client.list_skills_index.return_value = {
        "count": 1, "skills": [{"phase": "web", "name": "graphql-testing", "description": "GraphQL testing"}],
    }
    handle_skills([], client)
    client.list_skills_index.assert_called_once_with(phase="")
    out = capsys.readouterr().out
    assert "graphql-testing" in out


def test_skills_find_ranks_and_prints_matches(client, capsys):
    client.find_skills.return_value = {
        "count": 1, "skills": [{"phase": "web", "name": "jwt-none-algorithm-bypass", "description": "JWT bypass"}],
    }
    handle_skills(["find", "--mitre", "T1550.001", "jwt", "bypass"], client)
    client.find_skills.assert_called_once_with(
        query="jwt bypass", phase="", tags="", mitre="T1550.001", asset_type="", limit=8,
    )
    out = capsys.readouterr().out
    assert "jwt-none-algorithm-bypass" in out


def test_skills_find_no_matches(client, capsys):
    client.find_skills.return_value = {"count": 0, "skills": []}
    handle_skills(["find", "nonexistent-topic"], client)
    assert "No matching skills" in capsys.readouterr().out


def test_skills_get_prints_full_text(client, capsys):
    client.get_skill_file.return_value = {"path": "web/graphql-testing.md", "title": "GraphQL testing", "content": "# GraphQL testing\n\nfull body here"}
    handle_skills(["get", "graphql-testing"], client)
    client.get_skill_file.assert_called_once_with("graphql-testing")
    out = capsys.readouterr().out
    assert "full body here" in out


def test_skills_get_404(client, capsys):
    client.get_skill_file.side_effect = httpx.HTTPStatusError("boom", request=httpx.Request("GET", "http://x"), response=httpx.Response(404, request=httpx.Request("GET", "http://x")))
    handle_skills(["get", "does-not-exist"], client)
    assert "No skill found" in capsys.readouterr().out


def test_link_creates_edge_with_parsed_fields(client, capsys):
    client.graph_link.return_value = {
        "source_id": "host:a.test", "relationship": "shares_auth_cookie", "target_id": "host:b.test",
        "confidence": "likely", "hypothesis": True,
    }
    handle_link(["host:a.test", "shares_auth_cookie", "host:b.test", "same", "Set-Cookie", "domain"], client)
    client.graph_link.assert_called_once_with(
        engagement_id="eng1", source="host:a.test", target="host:b.test",
        relation="shares_auth_cookie", evidence="same Set-Cookie domain", confidence="likely", derived_from="",
    )
    assert "shares_auth_cookie" in capsys.readouterr().out


def test_link_usage_with_too_few_args(client, capsys):
    handle_link(["host:a.test", "same_app_as"], client)
    client.graph_link.assert_not_called()
    assert "Usage" in capsys.readouterr().out


def test_link_requires_engagement():
    c = MagicMock()
    c.active_engagement_id = None
    handle_link(["a", "b", "c", "evidence"], c)
    c.graph_link.assert_not_called()


def test_record_files_reasoned_finding_with_computed_confidence(client, capsys):
    client.record_finding.return_value = {
        "finding": {"id": "f1", "finding_type": "observation", "confidence": "confirmed", "claim_severity": "none"},
        "suppressed": False,
    }
    handle_record(["observation", "IP cluster", "3", "subdomains", "share", "a", "/24", "--severity", "low"], client)
    client.record_finding.assert_called_once_with(
        engagement_id="eng1", title="IP cluster", evidence="3 subdomains share a /24",
        finding_type="observation", claim_severity="low", description="", target="",
        tags=["operator_recorded"],
    )
    out = capsys.readouterr().out
    assert "Recorded finding" in out
    assert "computed" in out


def test_record_reports_fp_suppression(client, capsys):
    client.record_finding.return_value = {"finding": None, "suppressed": True, "suppressed_reason": "matches p1"}
    handle_record(["observation", "title", "evidence"], client)
    assert "Not filed" in capsys.readouterr().out


def test_record_usage_with_too_few_args(client, capsys):
    handle_record(["observation", "title"], client)
    client.record_finding.assert_not_called()
    assert "Usage" in capsys.readouterr().out
