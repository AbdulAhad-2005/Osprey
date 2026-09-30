from __future__ import annotations

from cli.harness.runtime import HarnessRuntime


class _FakeClient:
    base_url = "http://backend.test"

    def __init__(self) -> None:
        self.polls = [
            {"job_id": "j1", "status": "running", "progress": "half", "results_log": ["one"]},
            {"job_id": "j1", "status": "completed", "progress": "done", "results_log": ["one", "two"]},
        ]
        self.closed = False
        self.cancelled: list[str] = []

    def poll_job(self, job_id: str, *, wait_seconds: int = 3):
        assert job_id in {"j1", "cap-1"}
        return self.polls.pop(0)

    def job_result(self, job_id: str):
        assert job_id in {"j1", "cap-1"}
        return {"result": {"ok": True}}

    def list_jobs(self, engagement_id: str, *, status: str = "", limit: int = 50):
        return [{"job_id": "j1", "engagement_id": engagement_id, "status": status or "running"}]

    def cancel_job(self, job_id: str):
        self.cancelled.append(job_id)
        return {"job_id": job_id, "status": "cancelled"}

    def close(self) -> None:
        self.closed = True

    def reconnect(self, base_url: str | None = None) -> None:
        if base_url:
            self.base_url = base_url.rstrip("/")


class _InvestigationClient(_FakeClient):
    def __init__(self) -> None:
        super().__init__()
        self.steps = [
            {
                "run_id": "run-1",
                "revision": "rev-7",
                "status": "ready",
                "state_summary": "Two useful opportunities remain.",
                "opportunities": [
                    {
                        "id": "lower",
                        "capability": "capability-a",
                        "label": "Lower priority",
                        "priority": 0.4,
                    },
                    {
                        "id": "higher",
                        "capability": "capability-b",
                        "label": "Higher priority",
                        "priority": 0.9,
                        "rationale": "backend ranked this highest",
                    },
                ],
                "active_jobs": [],
            },
            {
                "run_id": "run-1",
                "revision": "rev-8",
                "status": "complete",
                "state_summary": "Surface exhausted.",
                "opportunities": [],
                "active_jobs": [],
            },
        ]
        self.executions: list[dict] = []
        self.polls = [
            {
                "job_id": "cap-1",
                "status": "completed",
                "progress": "done",
                "results_log": ["capability evidence saved"],
            }
        ]

    def investigation_step(self, engagement_id: str, *, run_id: str = ""):
        assert engagement_id == "eng-1"
        return self.steps.pop(0)

    def execute_investigation_step(self, **payload):
        self.executions.append(payload)
        return {
            "decision": {"opportunity_id": payload["opportunity_id"]},
            "job": {"job_id": "cap-1", "status": "queued"},
        }


def test_deterministic_job_uses_runtime_lifecycle_without_loading_llm() -> None:
    runtime = HarnessRuntime(_FakeClient())

    events = list(
        runtime.drive_job(lambda: {"job_id": "j1", "status": "queued", "results_log": []})
    )

    assert [event.type for event in events] == [
        "job_started",
        "job_log",
        "job_progress",
        "job_log",
        "job_progress",
        "job_completed",
    ]
    assert runtime.llm.runner is None
    assert runtime.tool_gateway._loaded is False
    assert events[-1].data["result"] == {"result": {"ok": True}}


def test_binding_is_harness_state_and_same_binding_keeps_driver() -> None:
    runtime = HarnessRuntime(_FakeClient())
    runner = type("FakeRunner", (), {"reset": lambda self: None, "messages": []})()
    runtime.llm.runner = runner

    runtime.bind_engagement("eng-1", target="example.test")
    assert runtime.llm.runner is None

    runtime.llm.runner = runner
    runtime.bind_engagement("eng-1", target="example.test")
    assert runtime.llm.runner is runner

    runtime.bind_engagement("eng-2", target="other.test")
    assert runtime.llm.runner is None


def test_transcript_and_detail_mode_are_isolated_per_runtime() -> None:
    first = HarnessRuntime(_FakeClient())
    second = HarnessRuntime(_FakeClient())

    first.transcript.start({"tool_name": "httpx_probe"})
    first.transcript.set_detail_mode("verbose")

    assert len(first.transcript.recent()) == 1
    assert first.transcript.detail_mode == "verbose"
    assert second.transcript.recent() == []
    assert second.transcript.detail_mode == "preview"


def test_job_controls_are_engagement_scoped_by_runtime() -> None:
    client = _FakeClient()
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")

    assert runtime.list_jobs(status="running") == [
        {"job_id": "j1", "engagement_id": "eng-1", "status": "running"}
    ]
    assert runtime.cancel_job("j1")["status"] == "cancelled"
    assert client.cancelled == ["j1"]


def test_reconnect_clears_runtime_and_gateway_binding() -> None:
    runtime = HarnessRuntime(_FakeClient())
    runtime.bind_engagement("eng-1", target="example.test")

    runtime.reconnect("http://other-backend.test/")

    assert runtime.base_url == "http://other-backend.test"
    assert runtime.active_engagement_id is None
    assert runtime.active_target is None
    assert runtime.tool_gateway.engagement_id == ""
    assert runtime.tool_gateway.target == ""


def test_deterministic_investigation_selects_only_highest_backend_priority() -> None:
    client = _InvestigationClient()
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")

    events = list(runtime.start_investigation())

    assert client.executions == [
        {
            "engagement_id": "eng-1",
            "run_id": "run-1",
            "opportunity_id": "higher",
            "expected_revision": "rev-7",
            "driver": "deterministic",
            "rationale": "backend ranked this highest",
        }
    ]
    assert [event.type for event in events] == [
        "state",
        "opportunities",
        "decision",
        "capability_started",
        "capability_log",
        "capability_progress",
        "capability_completed",
        "state",
        "opportunities",
        "complete",
    ]
    assert runtime.session.investigation.status == "complete"


def test_pause_resume_reattaches_backend_active_job_without_new_decision() -> None:
    client = _InvestigationClient()
    client.steps = [
        {
            "run_id": "run-2",
            "revision": "rev-2",
            "status": "waiting",
            "state_summary": "Capability is still active.",
            "opportunities": [],
            "active_jobs": [{"job_id": "cap-1", "status": "running"}],
        },
        {
            "run_id": "run-2",
            "revision": "rev-3",
            "status": "complete",
            "state_summary": "Done.",
            "opportunities": [],
            "active_jobs": [],
        },
    ]
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    runtime.session.investigation.reset(run_id="run-2")
    runtime.session.investigation.status = "paused"

    events = list(runtime.resume_investigation())

    assert client.executions == []
    assert any(event.type == "capability_started" and event.data["resumed"] for event in events)
    assert events[-1].type == "complete"


def test_cancel_investigation_cancels_only_active_capability_job() -> None:
    client = _FakeClient()
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    runtime.session.investigation.status = "running"
    runtime.session.investigation.active_job_id = "cap-9"

    result = runtime.cancel_investigation()

    assert result == {"job_id": "cap-9", "status": "cancelled"}
    assert client.cancelled == ["cap-9"]
    assert runtime.session.investigation.status == "cancelled"


def test_runtime_has_no_llm_opportunity_picker() -> None:
    """Architecture guard: there is exactly one opportunity-picking driver
    (the no-LLM deterministic baseline). A real LLM operator drives typed
    tools directly through ``runtime.llm`` — see AGENTS.md point 4 and
    cli/commands/slash.py's ``/scan`` routing. Resurrecting a driver that
    lets the model pick only from a server-computed opaque menu is exactly
    the anti-pattern this guard exists to catch."""
    runtime = HarnessRuntime(_FakeClient())
    assert not hasattr(runtime, "llm_opportunity")


class _SupervisedClient(_InvestigationClient):
    """Same deterministic step/execute fixture as _InvestigationClient, plus
    list_findings for the checkpoint trigger."""

    def __init__(self, findings: list[dict] | None = None) -> None:
        super().__init__()
        self._findings = findings or []

    def list_findings(self, engagement_id: str, *, limit: int = 100, **_kwargs):
        assert engagement_id == "eng-1"
        return self._findings


def test_supervised_driver_never_checkpoints_when_nothing_notable_happens() -> None:
    """The whole point: zero LLM calls for a run with no high-severity
    findings and fewer than checkpoint_every completions."""
    client = _SupervisedClient()
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    calls: list[str] = []
    runtime.drive_prompt = lambda prompt, sink: calls.append(prompt) or True  # type: ignore[method-assign]

    events = list(runtime.start_supervised_investigation())

    assert calls == []
    assert not any(e.type.startswith("checkpoint") for e in events)
    assert events[-1].type == "complete"


def test_supervised_driver_checkpoints_on_new_high_severity_finding() -> None:
    client = _SupervisedClient(findings=[
        {"id": "f1", "title": "Critical RCE", "claim_severity": "critical"},
        {"id": "f2", "title": "Low-severity note", "claim_severity": "low"},
    ])
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    prompts: list[str] = []
    runtime.drive_prompt = lambda prompt, sink: prompts.append(prompt) or True  # type: ignore[method-assign]

    events = list(runtime.start_supervised_investigation())

    assert len(prompts) >= 1
    assert "high-severity" in prompts[0] and "Critical RCE" in prompts[0]
    assert "Low-severity note" not in prompts[0]
    checkpoint_types = [e.type for e in events if e.type.startswith("checkpoint")]
    assert checkpoint_types[0] == "checkpoint_started"
    assert "checkpoint_completed" in checkpoint_types


def test_supervised_driver_does_not_re_checkpoint_the_same_finding() -> None:
    client = _SupervisedClient(findings=[{"id": "f1", "title": "Critical RCE", "claim_severity": "critical"}])
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    prompts: list[str] = []
    runtime.drive_prompt = lambda prompt, sink: prompts.append(prompt) or True  # type: ignore[method-assign]

    list(runtime.start_supervised_investigation())

    assert len(prompts) == 1


def test_supervised_driver_checkpoints_after_n_completions_with_no_findings() -> None:
    client = _SupervisedClient()
    client.steps = [
        {
            "run_id": "run-1", "revision": f"rev-{i}", "status": "ready",
            "state_summary": "one opportunity", "active_jobs": [],
            "opportunities": [{"id": f"opp-{i}", "capability": "cap", "label": "x", "priority": 1.0}],
        }
        for i in range(3)
    ] + [{"run_id": "run-1", "revision": "rev-done", "status": "complete", "state_summary": "done", "opportunities": [], "active_jobs": []}]
    client.polls = [
        {"job_id": "cap-1", "status": "completed", "progress": "done", "results_log": []}
        for _ in range(3)
    ]
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    runtime.supervised.checkpoint_every = 2
    prompts: list[str] = []
    runtime.drive_prompt = lambda prompt, sink: prompts.append(prompt) or True  # type: ignore[method-assign]

    events = list(runtime.start_supervised_investigation())

    assert len(prompts) == 1
    assert "2 opportunities completed" in prompts[0]
    assert events[-1].type == "complete"


def test_supervised_driver_checkpoint_failure_is_non_fatal() -> None:
    client = _SupervisedClient(findings=[{"id": "f1", "title": "Critical RCE", "claim_severity": "critical"}])
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")

    def _boom(prompt, sink):
        raise RuntimeError("model backend unreachable")

    runtime.drive_prompt = _boom  # type: ignore[method-assign]

    events = list(runtime.start_supervised_investigation())

    checkpoint_completed = [e for e in events if e.type == "checkpoint_completed"]
    assert checkpoint_completed and checkpoint_completed[0].data["succeeded"] is False
    assert events[-1].type == "complete"  # the deterministic loop still finished


def test_start_supervised_investigation_sets_supervised_driver() -> None:
    client = _SupervisedClient()
    runtime = HarnessRuntime(client)
    runtime.bind_engagement("eng-1", target="example.test")
    runtime.drive_prompt = lambda prompt, sink: True  # type: ignore[method-assign]

    list(runtime.start_supervised_investigation())

    assert runtime.session.investigation.driver == "supervised"
