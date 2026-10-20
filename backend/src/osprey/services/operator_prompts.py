"""Interactive operator prompts — the backend side of "the agent pauses mid-run
to ask the operator a question, then continues once answered".

This is the substrate for the GUI/CLI feature where the agent raises a bounded
question (an exploitation gate, a scope decision) with proposed answers and the
run blocks on it instead of guessing or stopping. It is deliberately the same
shape as ``event_bus``: in-memory, single-process, asyncio-native — there is
exactly one backend process, so a pending question is just a Future the answer
endpoint resolves.

Flow:
  1. The foreground chat loop's injected ask-handler calls ``open_question(...)``
     and awaits the returned Future.
  2. The ``question`` event (id + text + options) streams to the client through
     the same chat event stream, so the browser can render option chips.
  3. The operator answers → ``POST /agent/question/{id}/answer`` → ``answer(...)``
     resolves the Future (and optionally flips a Rules-of-Engagement flag), so
     the awaiting tool call returns the chosen answer and the ReAct loop resumes.

Durable history is written to ``question_store`` so the Q&A survives a restart
and shows up in reasoning/context; the live coordination is in-memory only.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PendingQuestion:
    id: str
    engagement_id: str
    text: str
    options: list[dict[str, Any]]
    kind: str  # "gate" | "scope" | "choice"
    allow_freeform: bool
    grant_field: str  # "" | "allow_exploitation" | "destructive_actions_allowed"
    grant_true_values: list[str]
    created_at: float
    loop: asyncio.AbstractEventLoop
    future: "asyncio.Future[str]"
    answered: str | None = None
    _meta: dict[str, Any] = field(default_factory=dict)

    def event_payload(self) -> dict[str, Any]:
        """The wire shape the GUI's QuestionPrompt renders."""
        return {
            "id": self.id,
            "text": self.text,
            "options": self.options,
            "kind": self.kind,
            "allow_freeform": self.allow_freeform,
        }


_pending: dict[str, PendingQuestion] = {}


def open_question(
    engagement_id: str,
    *,
    question_id: str = "",
    text: str,
    options: list[dict[str, Any]] | None = None,
    kind: str = "choice",
    allow_freeform: bool = False,
    grant_field: str = "",
    grant_true_values: list[str] | None = None,
) -> PendingQuestion:
    """Register a pending question and return it (its ``future`` resolves to the
    operator's answer). Must be called from within the running event loop. A
    caller may pass ``question_id`` so the id it already streamed to the client
    matches the one the answer endpoint resolves."""
    eid = (engagement_id or "").strip()
    loop = asyncio.get_event_loop()
    pq = PendingQuestion(
        id=(question_id or uuid.uuid4().hex[:12]),
        engagement_id=eid,
        text=text.strip(),
        options=options or [],
        kind=kind if kind in ("gate", "scope", "choice") else "choice",
        allow_freeform=allow_freeform,
        grant_field=grant_field,
        grant_true_values=grant_true_values or [],
        created_at=time.time(),
        loop=loop,
        future=loop.create_future(),
    )
    _pending[pq.id] = pq
    # Durable record (best-effort; never block the live flow on persistence).
    try:
        from osprey.services import question_store

        # Tagged distinctly from the agent's own reasoning "open questions" so an
        # interactive gate isn't mistaken for an unresolved analytical question.
        question_store.raise_question(eid, text=pq.text, raised_by="operator_gate")
    except Exception:  # noqa: BLE001
        logger.debug("question_store.raise_question failed (non-fatal)", exc_info=True)
    return pq


def list_open(engagement_id: str) -> list[dict[str, Any]]:
    eid = (engagement_id or "").strip()
    return [pq.event_payload() for pq in _pending.values() if pq.engagement_id == eid]


def answer(question_id: str, answer_text: str) -> dict[str, Any] | None:
    """Resolve a pending question from any thread (FastAPI sync endpoints run in
    a worker thread; ``call_soon_threadsafe`` hops back to the loop). Applies an
    RoE grant if the question declared one. Returns a small result dict or None
    if the id is unknown / already answered."""
    pq = _pending.get(question_id)
    if pq is None or pq.answered is not None:
        return None
    pq.answered = answer_text
    granted: str | None = None
    if pq.grant_field:
        granted = _apply_grant(pq, answer_text)
    if not pq.future.done():
        pq.loop.call_soon_threadsafe(pq.future.set_result, answer_text)
    _pending.pop(question_id, None)
    try:  # mirror into durable history
        from osprey.services import question_store

        for q in question_store.list_open(pq.engagement_id):
            if q.text == pq.text:
                question_store.answer(q.id, answer_text=answer_text)
                break
    except Exception:  # noqa: BLE001
        logger.debug("question_store.answer failed (non-fatal)", exc_info=True)
    return {"id": pq.id, "engagement_id": pq.engagement_id, "answer": answer_text, "granted": granted}


def cancel_for_engagement(engagement_id: str, reason: str = "cancelled") -> None:
    """Resolve any open questions for an engagement (e.g. the run was stopped)
    so no tool call is left awaiting a Future that will never complete."""
    eid = (engagement_id or "").strip()
    for qid, pq in list(_pending.items()):
        if pq.engagement_id != eid:
            continue
        if not pq.future.done():
            pq.loop.call_soon_threadsafe(pq.future.set_result, reason)
        _pending.pop(qid, None)


def _apply_grant(pq: PendingQuestion, answer_text: str) -> str | None:
    """Flip a Rules-of-Engagement flag based on the chosen answer."""
    if pq.grant_field not in ("allow_exploitation", "destructive_actions_allowed"):
        return None
    grant = answer_text in pq.grant_true_values
    try:
        from osprey.services.engagement_store import get_engagement_store

        store = get_engagement_store()
        engagement = store.get(pq.engagement_id)
        if engagement is None:
            return None
        setattr(engagement.rules_of_engagement, pq.grant_field, grant)
        store.update(engagement)
        return f"{pq.grant_field}={grant}"
    except Exception:  # noqa: BLE001
        logger.warning("Failed to apply RoE grant for question %s", pq.id, exc_info=True)
        return None
