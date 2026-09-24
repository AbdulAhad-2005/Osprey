from __future__ import annotations

import pytest
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services import agent_common
from osprey.services.agent_assist import AssistState


@pytest.mark.anyio
async def test_execute_agent_tool_bridges_platform_script(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def fake_script_request(**kwargs):
        captured.update(kwargs)
        return ToolExecutionResponse(
            tool_name="script:python3",
            success=True,
            command="python3 /tmp/pentest/eid/check.py",
            stdout="FINDING|observed|info|url|Custom check|ok",
            finding_titles=["Custom check"],
            hybrid={"artifacts": {"stdout_path": "/tmp/out.txt"}},
        )

    monkeypatch.setattr(
        "osprey.services.script_exec.execute_script_request",
        fake_script_request,
    )
    monkeypatch.setattr(
        agent_common,
        "enrich_tool_result_for_agent",
        lambda base_text, *_args, **_kwargs: base_text,
    )

    result, success, response = await agent_common.execute_agent_tool(
        tool_name="platform_script",
        tool_args={"script_content": "print('ok')", "language": "python3", "timeout": 45},
        engagement_id="eid",
        run_id="rid",
        assist_state=AssistState(),
        target="example.com",
        phase="recon",
    )

    assert success is True
    assert response is not None
    assert response.tool_name == "script:python3"
    assert "STDOUT:" in result
    assert captured["code"] == "print('ok')"
    assert captured["engagement_id"] == "eid"
    assert captured["run_id"] == "rid"
    assert captured["timeout"] == 45


@pytest.mark.anyio
async def test_execute_agent_tool_bridges_platform_shell(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def fake_shell_request(**kwargs):
        captured.update(kwargs)
        return ToolExecutionResponse(
            tool_name="shell:bash",
            success=True,
            command="curl -I https://example.com",
            stdout="HTTP/2 200",
        )

    monkeypatch.setattr(
        "osprey.services.shell_exec.execute_shell_request",
        fake_shell_request,
    )
    monkeypatch.setattr(
        agent_common,
        "enrich_tool_result_for_agent",
        lambda base_text, *_args, **_kwargs: base_text,
    )

    result, success, response = await agent_common.execute_agent_tool(
        tool_name="platform_shell",
        tool_args={"command": "curl -I https://example.com", "timeout": 60},
        engagement_id="eid",
        run_id="rid",
        assist_state=AssistState(),
        target="example.com",
        phase="recon",
    )

    assert success is True
    assert response is not None
    assert response.tool_name == "shell:bash"
    assert "HTTP/2 200" in result
    assert captured["command"] == "curl -I https://example.com"
    assert captured["engagement_id"] == "eid"
    assert captured["run_id"] == "rid"
    assert captured["timeout"] == 60
