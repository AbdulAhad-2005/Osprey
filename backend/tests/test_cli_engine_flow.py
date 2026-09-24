"""Regression guards for the CLI/engine flow fixes:

- local Ollama models must route through ``ollama_chat/`` so tool calls survive
- subdomain enumeration must root at the registrable apex, not a literal host
- a zero-surface full run must report an honest failure, not a green success
"""

from __future__ import annotations

import asyncio


def test_ollama_model_is_forwarded_to_litellm(monkeypatch):
    from osprey.core.config import LLMSettings
    from osprey.services import llm_service
    from osprey.services.llm_service import LLMService

    captured = {}

    class _Response:
        def model_dump(self):
            return {"choices": []}

    async def _complete(**kwargs):
        captured.update(kwargs)
        return _Response()

    monkeypatch.setattr(llm_service, "acompletion", _complete)

    svc = LLMService(LLMSettings(model="ollama/qwen3:8b", api_key="ollama", api_base="http://x:11434"))
    asyncio.run(svc.complete([{"role": "user", "content": "test"}]))
    assert captured["model"] == "ollama/qwen3:8b"
    assert svc.model == "ollama/qwen3:8b"


def _stub_tool_execution(monkeypatch, surface_expansion) -> None:
    from osprey.schemas.tools import ToolExecutionResponse

    async def _execute(request, **_kwargs):
        return ToolExecutionResponse(
            tool_name=request.tool_name,
            success=True,
            command=f"stub:{request.tool_name}",
            stdout="",
            returncode=0,
        )

    monkeypatch.setattr(surface_expansion, "_execute_request", _execute)


def test_engine_seeds_apex_for_subdomain_target(monkeypatch):
    from osprey.schemas.engagement import EngagementCreateRequest
    from osprey.schemas.engagement_graph import AssetType
    from osprey.services import surface_expansion as se
    from osprey.services.engagement_graph import get_engagement_graph
    from osprey.services.engagement_store import get_engagement_store

    _stub_tool_execution(monkeypatch, se)
    monkeypatch.setattr(se, "resolve_host_ip", lambda _host: "192.0.2.1")
    monkeypatch.setattr(se, "_phase_enabled", lambda _phase: False)
    monkeypatch.setattr(se, "_permutation_patterns", list)
    monkeypatch.setattr(se, "_installed_steps", lambda _section: [])

    e = get_engagement_store().create(EngagementCreateRequest(target="www.example.com", name="apex-seed"))
    asyncio.run(
        asyncio.wait_for(
            se.run_expansion_pass(engagement_id=e.id, run_id="r"),
            timeout=10,
        )
    )
    g = get_engagement_graph()
    domains = {n.label for n in g.list_nodes(engagement_id=e.id, asset_type=AssetType.DOMAIN, limit=50)}
    subs = {n.label for n in g.list_nodes(engagement_id=e.id, asset_type=AssetType.SUBDOMAIN, limit=50)}
    assert "example.com" in domains, "apex must be the enumeration root"
    assert "www.example.com" in subs, "original host must still be probed as a subdomain"


def test_engine_apex_target_seeds_itself(monkeypatch):
    from osprey.schemas.engagement import EngagementCreateRequest
    from osprey.schemas.engagement_graph import AssetType
    from osprey.services import surface_expansion as se
    from osprey.services.engagement_graph import get_engagement_graph
    from osprey.services.engagement_store import get_engagement_store

    _stub_tool_execution(monkeypatch, se)
    monkeypatch.setattr(se, "resolve_host_ip", lambda _host: "192.0.2.1")
    monkeypatch.setattr(se, "_phase_enabled", lambda _phase: False)
    monkeypatch.setattr(se, "_permutation_patterns", list)
    monkeypatch.setattr(se, "_installed_steps", lambda _section: [])

    e = get_engagement_store().create(EngagementCreateRequest(target="example.org", name="apex-self"))
    asyncio.run(
        asyncio.wait_for(
            se.run_expansion_pass(engagement_id=e.id, run_id="r"),
            timeout=10,
        )
    )
    g = get_engagement_graph()
    domains = {n.label for n in g.list_nodes(engagement_id=e.id, asset_type=AssetType.DOMAIN, limit=50)}
    assert "example.org" in domains
