"""tool_execution's claim-wait dedup — the gap a real conversation surfaced:
an investigation capability job and an LLM/subagent hand-running the same
tool+asset used to just both execute for real (tool_coverage_store.try_claim
was logged-and-ignored). Now the second caller waits a bounded window,
re-checking both the claim (releases when the holder finishes) and the exec
cache (the holder's completion populates it) before ever falling through to
running a genuine duplicate.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services import tool_execution


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def _fake_response(tool_name: str) -> ToolExecutionResponse:
    return ToolExecutionResponse(tool_name=tool_name, success=True, stdout="real run output")


def test_claim_wait_resolves_via_cache_hit_without_running_the_tool():
    """The claim is held for the whole wait window, but a cached result
    appears mid-wait (the real holder finished and cached it) — this caller
    must return that result and NEVER call the tool itself."""
    eid = _make_engagement("claim-dedup-cache.test")
    mcp_call = AsyncMock(side_effect=AssertionError("must not run the tool for real — cache should resolve it first"))

    class _FakeCoverageStore:
        def try_claim(self, **_kw):
            return False  # held by "someone else" for the entire wait window

        def release(self, **_kw):
            pass

    class _FakeCache:
        def __init__(self):
            self.calls = 0

        def make_key(self, **_kw):
            return "k"

        def get(self, _key):
            self.calls += 1
            if self.calls >= 2:  # not on the very first poll — proves it actually waited/polled
                return _fake_response("whois_lookup")
            return None

    with (
        patch.object(tool_execution, "_CLAIM_WAIT_SECONDS", 1.0),
        patch.object(tool_execution, "_CLAIM_POLL_INTERVAL", 0.05),
        patch.object(tool_execution, "get_tool_coverage_store", return_value=_FakeCoverageStore()),
        patch.object(tool_execution, "get_exec_cache", return_value=_FakeCache()),
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="whois_lookup",
            params={"target": "claim-dedup-cache.test"},
            engagement_id=eid,
            record_findings=False,
        )))

    assert result.cache_hit is True
    mcp_call.assert_not_called()


def test_claim_wait_proceeds_for_real_once_the_holder_releases():
    """The claim is held for one poll, then released — this caller must run
    the tool for real once it acquires the claim, not wait out the full window."""
    eid = _make_engagement("claim-dedup-release.test")
    mcp_call = AsyncMock(return_value=_fake_response("whois_lookup"))

    class _FakeCoverageStore:
        def __init__(self):
            self.attempts = 0

        def try_claim(self, **_kw):
            self.attempts += 1
            return self.attempts >= 2  # released by the second attempt

        def release(self, **_kw):
            pass

    class _FakeCache:
        def make_key(self, **_kw):
            return "k"

        def get(self, _key):
            return None

        def set(self, _key, _response):
            pass

    with (
        patch.object(tool_execution, "_CLAIM_WAIT_SECONDS", 1.0),
        patch.object(tool_execution, "_CLAIM_POLL_INTERVAL", 0.05),
        patch.object(tool_execution, "get_tool_coverage_store", return_value=_FakeCoverageStore()),
        patch.object(tool_execution, "get_exec_cache", return_value=_FakeCache()),
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="whois_lookup",
            params={"target": "claim-dedup-release.test"},
            engagement_id=eid,
            record_findings=False,
        )))

    assert result.cache_hit is False
    mcp_call.assert_called_once()


def test_claim_wait_times_out_and_runs_anyway():
    """Nothing resolves the wait (claim never releases, cache never fills) —
    must still fall through to a real run, never block indefinitely. This is
    the safety property tool_coverage_store's own docstring promises: a bug
    in claim bookkeeping (or a genuinely slow holder) can never wedge
    execution."""
    eid = _make_engagement("claim-dedup-timeout.test")
    mcp_call = AsyncMock(return_value=_fake_response("whois_lookup"))

    class _FakeCoverageStore:
        def try_claim(self, **_kw):
            return False  # never released

        def release(self, **_kw):
            pass

    class _FakeCache:
        def make_key(self, **_kw):
            return "k"

        def get(self, _key):
            return None  # never populated

        def set(self, _key, _response):
            pass

    with (
        patch.object(tool_execution, "_CLAIM_WAIT_SECONDS", 0.15),
        patch.object(tool_execution, "_CLAIM_POLL_INTERVAL", 0.05),
        patch.object(tool_execution, "get_tool_coverage_store", return_value=_FakeCoverageStore()),
        patch.object(tool_execution, "get_exec_cache", return_value=_FakeCache()),
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="whois_lookup",
            params={"target": "claim-dedup-timeout.test"},
            engagement_id=eid,
            record_findings=False,
        )))

    assert result.cache_hit is False
    mcp_call.assert_called_once()


def test_claim_immediately_available_never_waits():
    """The common case — no collision at all — must not pay any wait cost;
    try_claim succeeding on the first call skips the loop entirely."""
    eid = _make_engagement("claim-dedup-none.test")
    mcp_call = AsyncMock(return_value=_fake_response("whois_lookup"))

    class _FakeCoverageStore:
        def try_claim(self, **_kw):
            return True

        def release(self, **_kw):
            pass

    with (
        patch.object(tool_execution, "_CLAIM_WAIT_SECONDS", 5.0),
        patch.object(tool_execution, "get_tool_coverage_store", return_value=_FakeCoverageStore()),
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="whois_lookup",
            params={"target": "claim-dedup-none.test"},
            engagement_id=eid,
            record_findings=False,
            use_cache=False,
        )))

    assert result.cache_hit is False
    mcp_call.assert_called_once()
