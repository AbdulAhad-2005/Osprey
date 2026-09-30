"""A 409 (stale revision) from execute_investigation_step means "the world
moved between sense and act — recompute and retry," which is normal,
expected optimistic-concurrency behavior. Observed live: this had NO retry
cap at all, so when the same opportunity kept losing the race (a crt_sh_query
opportunity against geo.tv), the CLI driver spun retrying it forever —
hundreds of "Evidence changed before scheduling; replanning." lines with no
way out short of Ctrl+C. This must be bounded: a few retries should recover
transparently, but a persistent conflict must surface as a clear stop, never
an infinite loop.
"""

from __future__ import annotations

from cli.harness.drivers import _MAX_CONSECUTIVE_STALE
from cli.harness.runtime import HarnessRuntime


class _Stale409(Exception):
    def __init__(self) -> None:
        super().__init__("stale investigation revision")
        self.response = type("R", (), {"status_code": 409})()


class _FakeClient:
    base_url = "http://backend.test"

    def __init__(self, *, fail_times: int) -> None:
        self.fail_times = fail_times
        self.attempts = 0
        self.job_started = False
        self.polls = [
            {"job_id": "cap-1", "status": "completed", "progress": "done", "results_log": []},
        ]

    def investigation_step(self, engagement_id: str, *, run_id: str = ""):
        if self.job_started:
            return {
                "run_id": "run-1", "revision": "rev-done", "status": "complete",
                "state_summary": "Surface exhausted.", "opportunities": [], "active_jobs": [],
            }
        return {
            "run_id": "run-1",
            "revision": "rev-stable",
            "status": "ready",
            "state_summary": "One opportunity keeps losing the replan race.",
            "opportunities": [
                {"id": "opp-1", "capability": "discover_related_domains", "label": "crt_sh_query", "priority": 1.0},
            ],
            "active_jobs": [],
        }

    def execute_investigation_step(self, **payload):
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise _Stale409()
        self.job_started = True
        return {"decision": {"opportunity_id": payload["opportunity_id"]}, "job": {"job_id": "cap-1", "status": "queued"}}

    def poll_job(self, job_id: str, *, wait_seconds: int = 3):
        return self.polls.pop(0)

    def job_result(self, job_id: str):
        return {"result": {"ok": True}}

    def list_jobs(self, engagement_id: str, *, status: str = "", limit: int = 50):
        return []

    def cancel_job(self, job_id: str):
        return {"job_id": job_id, "status": "cancelled"}

    def close(self) -> None:
        pass

    def reconnect(self, base_url: str | None = None) -> None:
        pass


def test_a_few_stale_retries_recover_and_the_job_still_starts(monkeypatch) -> None:
    monkeypatch.setattr("cli.harness.drivers.time.sleep", lambda _: None)
    client = _FakeClient(fail_times=3)
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="geo.tv")

    events = list(runtime.start_investigation())

    assert client.attempts == 4  # 3 failures + 1 success
    event_types = [e.type for e in events]
    assert event_types.count("state_stale") == 3
    assert "capability_started" in event_types
    assert "error" not in event_types


def test_persistent_stale_conflict_stops_instead_of_looping_forever(monkeypatch) -> None:
    monkeypatch.setattr("cli.harness.drivers.time.sleep", lambda _: None)
    # Fails far more times than the cap allows — proves the loop terminates
    # rather than retrying without limit.
    client = _FakeClient(fail_times=_MAX_CONSECUTIVE_STALE + 50)
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="geo.tv")

    events = list(runtime.start_investigation())

    assert client.attempts == _MAX_CONSECUTIVE_STALE + 1
    assert events[-1].type == "error"
    assert "crt_sh_query" in events[-1].data["message"]
    assert runtime.session.investigation.status == "blocked"
