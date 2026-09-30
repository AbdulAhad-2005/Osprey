from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable

from cli.agent.loop import Event
from cli.agent.tools import EmbeddedToolGateway
from cli.harness.drivers import (
    CapabilityJobDriver,
    DeterministicInvestigationDriver,
    LLMDriver,
    SupervisedDeterministicDriver,
)
from cli.harness.session import HarnessSession
from cli.harness.workers import WorkerManager


class HarnessRuntime:
    """Single orchestration owner for a CLI process.

    The object is also a compatibility façade over ``APIClient`` so the large
    read-only slash-command surface can be migrated without duplicating its
    transport methods.  New orchestration belongs on this class, never on the
    HTTP client or in an individual command handler.
    """

    def __init__(self, client: Any) -> None:
        self.client = client
        self.session = HarnessSession()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._event_stop = threading.Event()
        self._event_thread: threading.Thread | None = None
        self.tool_gateway = EmbeddedToolGateway(client.base_url)
        self.llm = LLMDriver(self)
        self.capability_jobs = CapabilityJobDriver(self)
        # The only opportunity-picking driver — reserved for the no-LLM
        # baseline. A real LLM operator drives typed tools directly through
        # ``self.llm`` (LLMDriver's ReAct loop), never through this.
        self.deterministic = DeterministicInvestigationDriver(self)
        # The "blanket": the deterministic engine above runs itself; this
        # wraps it with occasional, unrestricted LLM checkpoints (never a
        # picker) — see SupervisedDeterministicDriver's own docstring.
        self.supervised = SupervisedDeterministicDriver(self)
        self.workers = WorkerManager(self)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)

    @property
    def base_url(self) -> str:
        return self.client.base_url

    @property
    def active_engagement_id(self) -> str | None:
        return self.session.engagement_id

    @property
    def active_target(self) -> str | None:
        return self.session.target

    @property
    def active_agent(self) -> Any:
        return self.session.active_agent

    @property
    def transcript(self):
        return self.session.transcript

    @active_agent.setter
    def active_agent(self, value: Any) -> None:
        self.set_agent(value)

    def _event_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
        return self._loop

    def drive_prompt(self, prompt: str, sink: Callable[[Event], None]) -> bool:
        if not prompt.strip():
            return True
        loop = self._event_loop()
        asyncio.set_event_loop(loop)
        task = loop.create_task(self.llm.drive(prompt, sink))
        try:
            return bool(loop.run_until_complete(task))
        except KeyboardInterrupt:
            task.cancel()
            try:
                loop.run_until_complete(task)
            except asyncio.CancelledError:
                pass
            return False

    def drive_job(self, starter: Callable[[], dict[str, Any]]):
        """Run an explicit operator-selected utility; not investigation intelligence."""
        return self.capability_jobs.drive_job(starter=starter)

    def start_investigation(self, *, run_id: str = ""):
        """Run the deterministic, no-LLM opportunity engine — the baseline
        that works with no API key configured. A real LLM operator should
        drive typed tools directly through ``self.llm`` instead (see
        cli/commands/slash.py's ``/scan``), never through this picker."""
        if not self.active_engagement_id:
            raise RuntimeError("No engagement bound.")
        self.session.investigation.reset(run_id=run_id, driver="deterministic")
        return self.deterministic.drive()

    def start_supervised_investigation(self, *, run_id: str = ""):
        """Run the deterministic engine unattended, with an LLM checking in
        at bounded checkpoints — see SupervisedDeterministicDriver. Requires
        an LLM to actually be configured (checkpoints call ``self.llm``);
        with none configured this degrades to the same no-LLM baseline as
        ``start_investigation`` since every checkpoint's ``drive_prompt``
        call simply has nothing to drive."""
        if not self.active_engagement_id:
            raise RuntimeError("No engagement bound.")
        self.session.investigation.reset(run_id=run_id, driver="supervised")
        return self.supervised.drive()

    def pause_investigation(self) -> bool:
        state = self.session.investigation
        if state.status not in {"running", "waiting", "blocked"}:
            return False
        state.status = "paused"
        return True

    def resume_investigation(self):
        state = self.session.investigation
        if state.status != "paused":
            raise RuntimeError("No paused investigation to resume.")
        state.status = "running"
        selected = self.supervised if state.driver == "supervised" else self.deterministic
        return selected.drive()

    def cancel_investigation(self) -> dict[str, Any] | None:
        state = self.session.investigation
        state.status = "cancelled"
        job_id = state.active_job_id
        state.active_job_id = ""
        state.active_opportunity_id = ""
        return self.client.cancel_job(job_id) if job_id else None

    def run_fast_scan(self, target: str):
        engagement_id = self.active_engagement_id
        if not engagement_id:
            raise RuntimeError("No engagement bound.")
        return self.drive_job(
            lambda: self.client.start_fast_scan_job(engagement_id, target)
        )

    def list_jobs(self, *, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        engagement_id = self.active_engagement_id
        if not engagement_id:
            raise RuntimeError("No engagement bound.")
        return self.client.list_jobs(engagement_id, status=status, limit=limit)

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self.client.poll_job(job_id, wait_seconds=0)

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        return self.client.cancel_job(job_id)

    def start_event_stream(self, sink: Callable[[str, str, dict[str, Any]], None]) -> None:
        """Start the single background activity stream for this session."""
        if self._event_thread is not None and self._event_thread.is_alive():
            return
        self._event_stop.clear()

        def _listen() -> None:
            watched: str | None = None
            while not self._event_stop.is_set():
                engagement_id = self.active_engagement_id
                if not engagement_id:
                    self._event_stop.wait(1)
                    continue
                watched = engagement_id
                try:
                    for event_type, data in self.client.stream_events(engagement_id):
                        if self._event_stop.is_set() or self.active_engagement_id != watched:
                            break
                        sink(data.get("source", ""), event_type, data)
                except Exception:
                    pass
                if not self._event_stop.is_set():
                    self._event_stop.wait(2)

        self._event_thread = threading.Thread(
            target=_listen, name="osprey-events", daemon=True
        )
        self._event_thread.start()

    def stop_event_stream(self) -> None:
        self._event_stop.set()
        thread = self._event_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
        self._event_thread = None

    def set_agent(self, agent: Any) -> None:
        if agent is self.session.active_agent:
            return
        self.session.active_agent = agent
        self.llm.reset()

    def reload_model(self) -> None:
        self.llm.reset()

    def conversation_messages(self) -> list[dict[str, Any]]:
        runner = self.llm.runner
        return list(runner.messages) if runner is not None else []

    def binding_changed(self) -> None:
        self.llm.reset()

    def bind_engagement(self, engagement_id: str | None, *, target: str = "") -> None:
        new_id = engagement_id or None
        new_target = target.strip() or None
        changed = new_id != self.session.engagement_id or (
            new_target is not None and new_target != self.session.target
        )
        self.session.engagement_id = new_id
        self.session.target = new_target
        self.tool_gateway.bind(engagement_id=new_id or "", target=new_target or "")
        if changed:
            self.binding_changed()
            self.session.investigation.reset()

    def reset_conversation(self) -> None:
        self.llm.reset()
        self.transcript.clear()

    def reconnect(self, base_url: str | None = None) -> None:
        self.client.reconnect(base_url)
        self.tool_gateway.configure(self.client.base_url)
        # Reconnect is a backend boundary: never carry an engagement selected
        # on the old backend into the new gateway, even when the gateway was
        # already loaded and its adapter could otherwise retain that identity.
        self.tool_gateway.bind(engagement_id="", target="")
        self.session.engagement_id = None
        self.session.target = None
        self.session.investigation.reset()
        self.llm.reset()

    def close(self) -> None:
        self.stop_event_stream()
        self.llm.reset()
        if self._loop is not None and not self._loop.is_closed():
            self._loop.close()
        self.client.close()


def get_runtime(owner: Any) -> HarnessRuntime:
    """Normalize a first-party runtime or wrap a transport at an API boundary.

    Production entry points construct and retain one runtime explicitly.  The
    transport is never mutated to cache harness state.
    """

    if isinstance(owner, HarnessRuntime):
        return owner
    return HarnessRuntime(owner)
