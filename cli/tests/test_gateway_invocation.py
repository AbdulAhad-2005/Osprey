import asyncio
from types import SimpleNamespace
from agent_core import tools


def test_each_gateway_supplies_its_binding_on_every_call(monkeypatch):
    seen = []
    def invoke(name, arguments, *, engagement_id):
        seen.append((name, arguments, engagement_id))
        return engagement_id
    monkeypatch.setattr(tools, "_SERVER_MODULE", SimpleNamespace(embedded_invoke_tool=invoke))
    a, b = tools.EmbeddedToolGateway("http://same-backend"), tools.EmbeddedToolGateway("http://same-backend")
    a.bind(engagement_id="a", target="a.test")
    b.bind(engagement_id="b", target="b.test")
    a._loaded = b._loaded = True
    async def scenario():
        return await asyncio.gather(a.call("platform_context", {}), b.call("nmap_service_scan", {"target": "b.test"}))
    assert asyncio.run(scenario()) == ["a", "b"]
    assert {eid for _, _, eid in seen} == {"a", "b"}
