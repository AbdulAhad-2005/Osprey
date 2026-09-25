"""Backend-LLM availability gate for platform_spawn_agent, and the read-only
contract of platform_pipeline / phase_supervisor.start_pipeline().

Root issue #1 (fixed earlier): driving the platform through an external MCP
client (opencode, Claude, etc.) with no reason to also configure the backend's
OWN separate LLM used to spawn a server-side PhaseAgent that failed opaquely
mid-run. `llm_configured()`/`llm_not_configured_message()` (llm_service.py) is
a usability check (key present AND the provider's runtime deps importable),
wired into JobStore.create_and_spawn(kind=AGENT) — the platform_spawn_agent
path — so it fails fast with one clear message instead of a wasted job slot.

Root issue #2 (the actual live bug this file now guards against): even with
that check in place, `phase_supervisor.start_pipeline()` — the function behind
platform_pipeline(action='start'), reachable from ANY MCP-connected external
harness — used to branch on `llm_configured()` too: if a backend key happened
to be configured for an unrelated CLI/GUI session, an MCP-connected harness's
read-only status call would silently spawn a second, unrelated backend agent.
The fix: start_pipeline() no longer calls llm_configured() at all — it is
unconditionally read-only, regardless of backend key state. The tests below
that used to assert the old branching behavior are replaced with the
regression test for this exact bug.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

from osprey.core.config import LLMSettings
from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services.job_store import get_job_store
from osprey.services.llm_service import llm_configured, llm_not_configured_message
from osprey.services import phase_supervisor


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


# --- llm_configured() ---

def test_llm_configured_true_when_api_key_present():
    settings = LLMSettings(model="groq/compound-mini", api_key="sk-real-key")
    with patch("osprey.services.llm_service.get_settings") as mock_settings:
        mock_settings.return_value.llm = settings
        assert llm_configured() is True


def test_llm_configured_false_when_api_key_empty():
    settings = LLMSettings(model="groq/compound-mini", api_key="")
    with patch("osprey.services.llm_service.get_settings") as mock_settings:
        mock_settings.return_value.llm = settings
        assert llm_configured() is False


def test_llm_configured_ollama_accepts_api_base_alone():
    settings = LLMSettings(model="ollama/llama3", api_key="", api_base="http://localhost:11434")
    with patch("osprey.services.llm_service.get_settings") as mock_settings:
        mock_settings.return_value.llm = settings
        assert llm_configured() is True


def test_llm_configured_false_when_provider_runtime_deps_missing():
    """Key presence alone isn't usability — a provider whose Python package
    isn't installed (e.g. gemini/vertex_ai needs google.auth) must report
    unconfigured, not crash opaquely on the first real completion() call."""
    settings = LLMSettings(model="vertex_ai/gemini-2.5-flash", api_key="sk-real-key")
    with patch("osprey.services.llm_service.get_settings") as mock_settings, \
         patch("osprey.services.llm_service._missing_runtime_deps", return_value=["google.auth"]):
        mock_settings.return_value.llm = settings
        assert llm_configured() is False


# --- phase_supervisor.start_pipeline(): ALWAYS read-only, regardless of backend key ---

def test_start_pipeline_always_readiness_only_regardless_of_llm_configured():
    """The actual regression test for the live bug: an MCP-connected external
    harness calling platform_pipeline(action='start') must never trigger
    backend auto-execution, whether or not a backend key happens to be
    configured (e.g. for an unrelated CLI/GUI session). start_pipeline() must
    not even consult llm_configured() — never reaches the point of needing an
    event loop / creating a background auto-executor task, either way."""
    for configured in (True, False):
        eid = _eid()
        with patch("osprey.services.llm_service.llm_configured", return_value=configured), \
             patch("asyncio.get_running_loop") as mock_loop:
            result = phase_supervisor.start_pipeline(eid)
            assert result["status"] == "readiness_only"
            assert result["engagement_id"] == eid
            assert "phase_readiness" in result
            assert "text" in result
            mock_loop.assert_not_called()


def test_start_pipeline_requires_engagement_id():
    result = phase_supervisor.start_pipeline("")
    assert result["status"] == "error"


# --- JobStore.create_and_spawn(kind=AGENT): raises before any budget/depth check ---

def test_create_and_spawn_agent_raises_when_llm_not_configured():
    eid = _eid()
    with patch("osprey.services.llm_service.llm_configured", return_value=False):
        try:
            get_job_store().create_and_spawn(
                JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
            )
            assert False, "expected ValueError"
        except ValueError as exc:
            assert str(exc) == llm_not_configured_message()


def test_create_and_spawn_tool_job_unaffected_by_llm_gate():
    """The LLM gate is AGENT-kind only — TOOL/SHELL/SCRIPT/EXPANSION jobs
    never touch the backend LLM and must not be blocked by it."""
    eid = _eid()

    async def _spawn():
        store = get_job_store()
        summary = store.create_and_spawn(
            JobStartRequest(kind=JobKind.TOOL, engagement_id=eid, tool_name="subfinder_scan", params={"domain": "example.com"})
        )
        record = store._jobs[summary.job_id]  # test-only introspection
        await record.task
        return summary

    with patch("osprey.services.llm_service.llm_configured", return_value=False), \
         patch(
             "osprey.services.tool_execution.execute_tool_request",
             new_callable=AsyncMock,
         ) as mock_exec:
        mock_exec.return_value = ToolExecutionResponse(tool_name="subfinder_scan", success=True, stdout="ok")
        summary = asyncio.run(_spawn())
        assert summary.job_id
