from __future__ import annotations

from types import SimpleNamespace

from cli.agent import tools as platform_tools
from cli.api.client import APIClient
from cli.harness import get_runtime


def test_changing_engagement_invalidates_driver_and_tracks_target() -> None:
    client = APIClient(base_url="http://backend.test")
    runtime = get_runtime(client)
    try:
        first_runner = SimpleNamespace(reset=lambda: None)
        runtime.llm.runner = first_runner
        runtime.bind_engagement("eng-a", target="a.example")

        assert runtime.llm.runner is None
        assert runtime.active_engagement_id == "eng-a"
        assert runtime.active_target == "a.example"

        retained_runner = SimpleNamespace(reset=lambda: None)
        runtime.llm.runner = retained_runner
        runtime.bind_engagement("eng-a", target="a.example")
        assert runtime.llm.runner is retained_runner

        runtime.bind_engagement("eng-b", target="b.example")
        assert runtime.llm.runner is None
        assert runtime.active_target == "b.example"
    finally:
        runtime.close()


def test_api_client_is_transport_only() -> None:
    client = APIClient(base_url="http://backend.test")
    try:
        assert not hasattr(client, "agent_runner")
        assert not hasattr(client, "agent_loop")
        assert not hasattr(client, "active_engagement_id")
        assert not hasattr(client, "active_target")
        assert not hasattr(client, "_harness_runtime")
    finally:
        client.close()


def test_reconfigure_clears_the_embedded_gateway_session(monkeypatch) -> None:
    configured: list[str] = []
    fake_server = SimpleNamespace(
        API_BASE="http://old",
        embedded_reconfigure=lambda url: configured.append(url),
    )
    monkeypatch.setattr(platform_tools, "_SERVER_MODULE", fake_server)

    platform_tools.reconfigure_server("http://new/")

    assert configured == ["http://new/"]


def test_bind_session_updates_the_canonical_gateway_context(monkeypatch) -> None:
    bound: list[tuple[str, str]] = []
    fake_server = SimpleNamespace(
        embedded_bind_session=lambda *, engagement_id, target="": bound.append(
            (engagement_id, target)
        ),
    )
    monkeypatch.setattr(platform_tools, "_SERVER_MODULE", fake_server)

    platform_tools.bind_session(engagement_id="eng-1", target="target.example")

    assert bound == [("eng-1", "target.example")]
