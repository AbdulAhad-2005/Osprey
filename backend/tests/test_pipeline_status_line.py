"""pipeline_status_line — the compact status platform_context surfaces so
active phase agents (however spawned — platform_spawn_agent, or the backend
auto-executor) are visible without a separate platform_pipeline(action='status')
call.

Regression coverage for a real bug: this used to short-circuit on a
`_PIPELINES`-registry-derived `status == "none"` check and return "not
started" WITHOUT ever looking at `active_agents` — so once nothing populated
that registry (true today: the registry was deleted, active-agent state comes
entirely from job_store), it would falsely report "not started" even while
real agent jobs were genuinely running. The line must be derived purely from
`active_agents`, never from a separate lifecycle-registry status string.
"""

from __future__ import annotations

from unittest.mock import patch

from osprey.services.phase_supervisor import pipeline_status_line


def test_no_active_agents():
    with patch(
        "osprey.services.phase_supervisor.pipeline_status",
        return_value={"status": "idle", "active_agents": []},
    ):
        assert pipeline_status_line("e1") == "agents: none active"


def test_active_agents_shown_regardless_of_status_field():
    """The actual regression test: active_agents present must drive the line
    even if some unrelated/stale 'status' value is also present in the dict."""
    status = {
        "status": "idle",  # deliberately inconsistent with active_agents, to prove
                            # the line doesn't trust `status` — only `active_agents`.
        "active_agents": [
            {"role": "recon"}, {"role": "recon"}, {"role": "vuln"},
        ],
    }
    with patch("osprey.services.phase_supervisor.pipeline_status", return_value=status):
        line = pipeline_status_line("e1")
        assert line.startswith("agents: running (")
        assert "recon:2" in line
        assert "vuln:1" in line


def test_missing_active_agents_key_treated_as_empty():
    with patch("osprey.services.phase_supervisor.pipeline_status", return_value={"status": "idle"}):
        assert pipeline_status_line("e1") == "agents: none active"
