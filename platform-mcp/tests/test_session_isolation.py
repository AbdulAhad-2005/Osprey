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


def test_embedded_reconfigure_replaces_the_pooled_http_client(server, monkeypatch) -> None:
    closed: list[bool] = []

    class _Client:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(server, "_HTTP_CLIENT", _Client())
    monkeypatch.setattr(server, "_clear_session", lambda: None)

    server.embedded_reconfigure("http://new-backend.test/")

    assert closed == [True]
    assert server._HTTP_CLIENT is None
    assert server.API_BASE == "http://new-backend.test"


def test_embedded_bind_keeps_target_identity_opaque(server, monkeypatch) -> None:
    monkeypatch.setattr(server, "_ensure_run_registered", lambda *_args: None)
    monkeypatch.setattr(server, "_persist_session", lambda: None)
    server._ENGAGEMENT_CACHE.clear()

    server.embedded_bind_session(engagement_id="eng-ip", target="192.0.2.1")

    assert server._SESSION_TARGET_KIND == "target"
    assert server._ENGAGEMENT_CACHE["eng-ip"] == {
        "target": "192.0.2.1",
        "kind": "target",
        "scope": "",
    }


def test_public_embedding_specs_match_the_mcp_adapter(server) -> None:
    public = {item["name"]: item for item in server.embedded_tool_specs()}
    adapter = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}

    assert public.keys() == adapter.keys()
    for name, tool in adapter.items():
        assert public[name]["description"] == (tool.description or "")
        assert public[name]["parameters"] == (
            tool.parameters or {"type": "object", "properties": {}}
        )


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


def test_pinned_is_false_when_the_explicit_id_matches_ambient_session(server, monkeypatch) -> None:
    """The noise a real operator transcript surfaced: every tool result in a
    normal single-engagement CLI session showed a "PINNED... bypassed the
    shared ambient session" notice, even though the CLI always passes
    engagement_id= by design and it always matched the ambient session — a
    warning about a divergence that never happened, on every single call.
    `.pinned` must only be True when the explicit id actually DIFFERS from
    the ambient one."""
    server._SESSION_ENGAGEMENT_ID = "eng-ambient"
    server._SESSION_TARGET = "ambient.example"
    server._ENGAGEMENT_CACHE["eng-ambient"] = {"target": "ambient.example", "kind": "domain", "scope": ""}
    server._ENGAGEMENT_RUN_IDS.setdefault("eng-ambient", "run-ambient")

    same = server._resolve_engagement("eng-ambient")
    assert same.pinned is False

    monkeypatch.setattr(server, "_get", lambda path, **_kw: {"id": "eng-other", "target": "other.example"})
    different = server._resolve_engagement("eng-other")
    assert different.pinned is True


def test_finding_body_uses_the_resolved_context_not_ambient_globals(server, monkeypatch) -> None:
    # Ambient session globals deliberately point somewhere ELSE — the whole
    # point of this test is that a pinned context must win over them, the
    # same concurrent-chat-safety property every _resolve_engagement caller
    # in server.py depends on.
    monkeypatch.setattr(server, "_SESSION_ENGAGEMENT_ID", "eng-ambient")
    monkeypatch.setattr(server, "SESSION_RUN_ID", "run-ambient")
    monkeypatch.setattr(server, "_SESSION_TARGET", "ambient.example")

    context = server._EngagementContext(
        engagement_id="eng-pinned",
        target="pinned.example",
        run_id="run-pinned",
        pinned=True,
    )

    posts: list[tuple[str, dict]] = []

    def fake_post(path: str, body: dict, **_kwargs):
        posts.append((path, body))
        if path == "/api/v1/observations/":
            return {"id": "obs-1"}
        return {"finding": {"id": "f-1"}, "suppressed": False}

    monkeypatch.setattr(server, "_post", fake_post)

    result = server._record_reasoned_finding(
        context=context,
        title="Reasoned relationship",
        evidence="shared certificate fingerprint",
    )

    assert isinstance(result, dict)
    assert len(posts) == 2  # observation, then file_finding
    for _path, body in posts:
        assert body["engagement_id"] == "eng-pinned"
        assert body["run_id"] == "run-pinned"
        assert body["target"] == "pinned.example"


def test_unpinned_call_is_rejected_once_multiple_engagements_are_bound(server, monkeypatch) -> None:
    """B5.2 — once this process has bound more than one target, the ambient
    "current" session is ambiguous, so an UNPINNED stateful resolve is rejected
    rather than silently routed to whichever was bound last. A PINNED call
    always resolves its own engagement regardless of ambient state."""
    server._clear_session()
    server._BOUND_ENGAGEMENTS.clear()
    server._ENGAGEMENT_CACHE.clear()
    server._ENGAGEMENT_RUN_IDS.clear()
    monkeypatch.setattr(server, "_ensure_run_registered", lambda *_a: None)
    monkeypatch.setattr(server, "_get", lambda path, **_kw: {
        "id": path.rsplit("/", 1)[-1], "target": f"{path.rsplit('/', 1)[-1]}.example",
    })

    # One engagement bound → unpinned ambient still works.
    server._SESSION_TARGET = "a.example"
    server._SESSION_ENGAGEMENT_ID = "eng-a"
    server._BOUND_ENGAGEMENTS.add("eng-a")
    server._ENGAGEMENT_CACHE["eng-a"] = {"target": "a.example", "kind": "domain", "scope": ""}
    assert server._resolve_engagement("").engagement_id == "eng-a"

    # A second target bound (e.g. a concurrent chat) → unpinned is now ambiguous.
    server._BOUND_ENGAGEMENTS.add("eng-b")
    with pytest.raises(RuntimeError, match="[Aa]mbiguous engagement"):
        server._resolve_engagement("")

    # A pinned call still resolves its own engagement, unaffected.
    assert server._resolve_engagement("eng-b").engagement_id == "eng-b"


def test_every_engagement_scoped_platform_tool_accepts_a_pin(server) -> None:
    scoped = {
        "platform_investigation_step",
        "platform_investigation_execute",
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
        "platform_fanout_assets",
        "platform_visualization",
        "platform_report_data",
        "platform_handoff",
    }

    for name in sorted(scoped):
        signature = inspect.signature(getattr(server, name))
        assert "engagement_id" in signature.parameters, name
