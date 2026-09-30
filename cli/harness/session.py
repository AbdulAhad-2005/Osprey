from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from cli.session import ToolTranscript


@dataclass
class InvestigationSession:
    """Lifecycle state for one resumable sense-decide-act run."""

    status: str = "idle"
    run_id: str = ""
    driver: str = "deterministic"
    revision: str = ""
    active_job_id: str = ""
    active_opportunity_id: str = ""

    def reset(self, *, run_id: str = "", driver: str = "deterministic") -> None:
        self.status = "idle"
        self.run_id = run_id
        self.driver = driver
        self.revision = ""
        self.active_job_id = ""
        self.active_opportunity_id = ""


@dataclass
class HarnessSession:
    """Mutable state owned by one CLI process.

    This is deliberately about harness state, not pentest domain types.  A
    target, port, host, or finding never changes how the runtime itself works.
    """

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    engagement_id: str | None = None
    target: str | None = None
    active_agent: Any = None
    transcript: ToolTranscript = field(default_factory=ToolTranscript)
    investigation: InvestigationSession = field(default_factory=InvestigationSession)

