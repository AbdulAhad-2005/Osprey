"""Plan 19 Part B — the deterministic driver launches work concurrently and
reaps it as it finishes (background-and-continue), instead of running one tool
to completion before starting the next. A slow tool no longer blocks the engine
and is never killed for being slow.

Driven against a scripted fake client so the concurrency is deterministic and
needs no backend.
"""
from __future__ import annotations

from types import SimpleNamespace

from cli.harness.drivers import DeterministicInvestigationDriver


class _FakeClient:
    def __init__(self) -> None:
        # Two independent opportunities, A higher priority than B.
        self._opps = {
            "a": {"id": "a", "capability": "probe_live_assets", "priority": 2.0,
                  "tool": "httpx_probe", "params": {"target": "a.test"}},
            "b": {"id": "b", "capability": "probe_live_assets", "priority": 1.0,
                  "tool": "naabu_port_scan", "params": {"target": "b.test"}},
        }
        self._completed: set[str] = set()
        self.calls: list[str] = []          # ordered method log
        self._rev = 0

    def investigation_step(self, engagement_id, run_id=""):
        self.calls.append("sense")
        self._rev += 1
        remaining = [o for oid, o in self._opps.items() if oid not in self._completed]
        return {
            "run_id": run_id or "r1",
            "revision": f"rev{self._rev}",
            "status": "complete" if not remaining else "ready",
            "state_summary": "",
            "opportunities": remaining,
            "active_jobs": [],
        }

    def execute_investigation_step(self, *, engagement_id, run_id, opportunity_id,
                                   expected_revision, driver, rationale):
        self.calls.append(f"execute:{opportunity_id}")
        return {"job": {"job_id": f"job-{opportunity_id}"}}

    def poll_job(self, job_id, *, wait_seconds=0):
        self.calls.append(f"poll:{job_id}")
        opp_id = job_id.replace("job-", "")
        self._completed.add(opp_id)   # completes on first poll
        return {"status": "completed", "results_log": []}

    def job_result(self, job_id):
        opp_id = job_id.replace("job-", "")
        tool = self._opps[opp_id]["tool"]
        return {"result": {"details": {"results": [{"tool": tool, "success": True}]}}}


class _FakeRuntime:
    def __init__(self, client) -> None:
        self.client = client
        self.active_engagement_id = "eng1"
        self.session = SimpleNamespace(
            investigation=SimpleNamespace(
                status="idle", run_id="r1", revision="", active_job_id="", active_opportunity_id="",
            )
        )


def test_driver_launches_both_opportunities_before_reaping_either():
    client = _FakeClient()
    driver = DeterministicInvestigationDriver(_FakeRuntime(client))

    events = list(driver.drive(wait_seconds=0))

    # Both opportunities were LAUNCHED (two execute calls) before the first job
    # was polled/reaped — that is background-and-continue, not one-at-a-time.
    first_poll = next((i for i, c in enumerate(client.calls) if c.startswith("poll:")), len(client.calls))
    executes_before_first_poll = [c for c in client.calls[:first_poll] if c.startswith("execute:")]
    assert set(executes_before_first_poll) == {"execute:a", "execute:b"}, client.calls

    # Both completed and the run reached a fixpoint.
    completed = [e for e in events if e.type == "capability_completed"]
    completed_opps = {e.data.get("opportunity_id") for e in completed}
    assert completed_opps == {"a", "b"}
    assert events[-1].type == "complete"


def test_driver_reaches_fixpoint_with_no_opportunities():
    """An engagement with nothing to do terminates immediately, no jobs launched."""
    client = _FakeClient()
    client._opps = {}
    driver = DeterministicInvestigationDriver(_FakeRuntime(client))
    events = list(driver.drive(wait_seconds=0))
    assert events[-1].type == "complete"
    assert not any(c.startswith("execute:") for c in client.calls)
