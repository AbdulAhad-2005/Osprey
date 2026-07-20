from __future__ import annotations

import asyncio
import json

from pentest_platform.schemas.agent_run import PhaseBrief
from pentest_platform.schemas.tools import ToolExecutionResponse
from pentest_platform.services.phase_agent import PhaseAgent


class _FakeLLM:
    model = "test/fake"

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, *args, **kwargs) -> dict:
        self.calls += 1
        if self.calls == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_subfinder",
                                    "type": "function",
                                    "function": {
                                        "name": "subfinder_scan",
                                        "arguments": json.dumps({"domain": "example.com"}),
                                    },
                                },
                                {
                                    "id": "call_wayback",
                                    "type": "function",
                                    "function": {
                                        "name": "waybackurls_discovery",
                                        "arguments": json.dumps({"domain": "example.com"}),
                                    },
                                },
                            ],
                        }
                    }
                ]
            }

        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Recon batch complete.",
                    }
                }
            ]
        }


def test_phase_agent_runs_same_turn_tool_calls_in_parallel(monkeypatch) -> None:
    active = 0
    max_active = 0

    async def fake_execute_agent_tool(**kwargs):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.05)
        active -= 1
        tool_name = kwargs["tool_name"]
        return (
            f"{tool_name} result",
            True,
            ToolExecutionResponse(tool_name=tool_name, success=True, stdout="ok"),
        )

    monkeypatch.setattr(
        "pentest_platform.services.phase_agent.execute_agent_tool",
        fake_execute_agent_tool,
    )

    async def fake_summarize_phase(*args, **kwargs):
        return PhaseBrief(phase="recon", target="example.com")

    monkeypatch.setattr(
        "pentest_platform.services.phase_agent.summarize_phase",
        fake_summarize_phase,
    )

    result = asyncio.run(
        PhaseAgent(llm=_FakeLLM()).run(
            "Run passive recon for example.com",
            phase="recon",
            max_turns=3,
        )
    )

    assert result.agent.success is True
    assert result.agent.total_tool_calls == 2
    assert [call.tool_name for call in result.agent.tool_calls] == [
        "subfinder_scan",
        "waybackurls_discovery",
    ]
    assert max_active == 2
