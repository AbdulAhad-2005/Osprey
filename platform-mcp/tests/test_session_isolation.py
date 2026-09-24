from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def server():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    previous_run_id = os.environ.pop("PENTEST_RUN_ID", None)
    try:
        spec = importlib.util.spec_from_file_location("osprey_platform_mcp_test", root / "server.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        if previous_run_id is not None:
            os.environ["PENTEST_RUN_ID"] = previous_run_id


def test_unidentified_clients_do_not_share_a_default_state_file(server) -> None:
    assert server._SESSION_STATE_FILE is None


def test_pinned_context_resolves_real_target_and_owns_a_stable_run(server, monkeypatch) -> None:
    server._clear_session()
    server._ENGAGEMENT_CACHE.clear()
    server._ENGAGEMENT_RUN_IDS.clear()
    server._REGISTERED_RUNS.clear()
    registered: list[tuple[str, str]] = []

    def fake_get(path: str, **_kwargs):
        engagement_id = path.rsplit("/", 1)[-1]
        return {"id": engagement_id, "target": f"{engagement_id}.example"}

    monkeypatch.setattr(server, "_get", fake_get)
    def fake_register(engagement_id: str, run_id: str) -> None:
        key = (engagement_id, run_id)
        if key not in registered:
            registered.append(key)

    monkeypatch.setattr(server, "_ensure_run_registered", fake_register)

    first = server._resolve_engagement("eng-a")
    repeated = server._resolve_engagement("eng-a")
    other = server._resolve_engagement("eng-b")

    assert first.target == "eng-a.example"
    assert first.pinned is True
    assert repeated.run_id == first.run_id
    assert other.run_id != first.run_id
    assert registered == [
        ("eng-a", first.run_id),
        ("eng-b", other.run_id),
    ]


def test_finding_body_uses_the_resolved_context_not_ambient_globals(server) -> None:
    context = server._EngagementContext(
        engagement_id="eng-pinned",
        target="pinned.example",
        run_id="run-pinned",
        pinned=True,
    )
    body = server._build_finding_body(
        context=context,
        title="Reasoned relationship",
        evidence="shared certificate fingerprint",
    )

    assert isinstance(body, dict)
    assert body["engagement_id"] == "eng-pinned"
    assert body["run_id"] == "run-pinned"
    assert body["target"] == "pinned.example"


def test_every_engagement_scoped_platform_tool_accepts_a_pin(server) -> None:
    scoped = {
        "platform_expand",
        "platform_pipeline",
        "platform_spawn_agent",
        "platform_delete_engagement",
        "platform_health",
        "platform_context",
        "platform_artifact",
        "platform_think",
        "platform_graph_link",
        "platform_graph_link_many",
        "platform_finalize_check",
        "platform_report_outline",
        "platform_memory_search",
        "platform_related",
        "platform_evidence_chain",
        "platform_attempts",
        "platform_record_finding",
        "platform_record_findings",
        "platform_findings",
        "platform_exploit_queue",
        "platform_exec",
        "platform_job_start",
        "platform_job_poll",
        "platform_job_result",
        "platform_shell",
        "platform_script",
        "platform_install",
        "platform_fanout",
        "platform_propose_skill",
        "platform_remember_preference",
        "platform_graph_query",
        "platform_thinking",
        "platform_fanout_assets",
        "platform_visualization",
        "platform_report_data",
        "platform_handoff",
    }

    for name in sorted(scoped):
        signature = inspect.signature(getattr(server, name))
        assert "engagement_id" in signature.parameters, name
