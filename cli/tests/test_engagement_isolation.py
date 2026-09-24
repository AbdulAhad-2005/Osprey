from __future__ import annotations

from types import SimpleNamespace

from cli.agent import tools as platform_tools
from cli.api.client import APIClient


def test_changing_engagement_invalidates_runner_and_tracks_target() -> None:
    client = APIClient(base_url="http://backend.test")
    try:
        first_runner = object()
        client.agent_runner = first_runner
        client._set_active_engagement("eng-a", target="a.example")

        assert client.agent_runner is None
        assert client.active_engagement_id == "eng-a"
        assert client.active_target == "a.example"

        retained_runner = object()
        client.agent_runner = retained_runner
        client._set_active_engagement("eng-a", target="a.example")
        assert client.agent_runner is retained_runner

        client._set_active_engagement("eng-b", target="b.example")
        assert client.agent_runner is None
        assert client.active_target == "b.example"
    finally:
        client.close()


def test_reconfigure_clears_the_embedded_gateway_session(monkeypatch) -> None:
    cleared: list[bool] = []
    fake_server = SimpleNamespace(
        API_BASE="http://old",
        _clear_session=lambda: cleared.append(True),
    )
    monkeypatch.setattr(platform_tools, "_SERVER_MODULE", fake_server)

    platform_tools.reconfigure_server("http://new/")

    assert fake_server.API_BASE == "http://new"
    assert cleared == [True]


def test_bind_session_updates_the_canonical_gateway_context(monkeypatch) -> None:
    registered: list[tuple[str, str]] = []
    persisted: list[bool] = []
    fake_server = SimpleNamespace(
        _SESSION_ENGAGEMENT_ID="",
        _SESSION_TARGET="",
        _SESSION_SWITCH_NOTICE="stale",
        _ENGAGEMENT_CACHE={},
        _ENGAGEMENT_RUN_IDS={},
        SESSION_RUN_ID="run-1",
        _ensure_run_registered=lambda engagement_id, run_id: registered.append(
            (engagement_id, run_id)
        ),
        _persist_session=lambda: persisted.append(True),
    )
    monkeypatch.setattr(platform_tools, "_SERVER_MODULE", fake_server)

    platform_tools.bind_session(engagement_id="eng-1", target="target.example")

    assert fake_server._SESSION_ENGAGEMENT_ID == "eng-1"
    assert fake_server._SESSION_TARGET == "target.example"
    assert fake_server._ENGAGEMENT_CACHE["eng-1"]["target"] == "target.example"
    assert fake_server._ENGAGEMENT_RUN_IDS == {"eng-1": "run-1"}
    assert registered == [("eng-1", "run-1")]
    assert persisted == [True]
