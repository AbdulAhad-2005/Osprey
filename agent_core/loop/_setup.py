"""Runner setup, budget, and context-management methods (mixin)."""

from __future__ import annotations
import asyncio
from collections.abc import AsyncIterator
from typing import Any
from agent_core.compaction import (
    ContextBudget,
    build_budget,
    build_summary_request,
    checkpoint_message,
    count_message_tokens,
    estimate_tokens,
    plan_compaction,
)
from agent_core.llm import complete
from agent_core.loop._helpers import (
    _COMPLETION_MAX_TOKENS,
    _STILL_WAITING_INTERVAL,
    _SPAWN_TOOL_SCHEMA,
    _ASK_TOOL_SCHEMA,
    Event,
)


class _SetupMixin:

    def reset(self) -> None:
        self.messages = []
        self._running_summary = ""
        self._call_outcomes = {}
        self._failure_counts = {}

    def _ensure_budget(self) -> ContextBudget:
        if self._budget is None:
            self._budget = build_budget(
                self.config.model,
                requested_max_tokens=_COMPLETION_MAX_TOKENS,
                tpm_budget_tokens=self.config.tool_schema_budget_tokens,
            )
        return self._budget

    def _tool_schemas(self) -> list[dict[str, Any]]:
        schemas = self._tool_gateway.schemas(
            budget_tokens=self.config.tool_schema_budget_tokens
        )
        if self._tool_filter is not None:
            schemas = [s for s in schemas if self._tool_filter(s["function"]["name"])]
        if self._allow_spawn:
            schemas.append(_SPAWN_TOOL_SCHEMA)
        if self._ask_handler is not None:
            schemas.append(_ASK_TOOL_SCHEMA)
        return schemas

    async def _complete_with_feedback(self, tool_schemas: list[dict[str, Any]]) -> AsyncIterator[Event]:
        """Run one ``complete()`` call, yielding a periodic ``llm_still_waiting``
        event every ``_STILL_WAITING_INTERVAL`` seconds while it's in flight, then
        exactly one final ``llm_result`` event carrying ``{"response": ...}`` on
        success or ``{"error": exc}`` on failure.

        ``complete()`` already retries transient provider errors internally (3
        attempts x up to 120s each) — a genuinely overloaded provider can take
        several minutes to finally fail, during which the caller previously had
        no way to distinguish "still working" from "hung". Polling with
        ``asyncio.wait(..., timeout=...)`` gives this loop a chance to report
        elapsed time without needing complete() to know anything about events.
        """
        task = asyncio.ensure_future(
            complete(
                config=self.config, messages=self.messages,
                tools=tool_schemas, max_tokens=_COMPLETION_MAX_TOKENS,
            )
        )
        waited = 0.0
        try:
            while True:
                done, _pending = await asyncio.wait({task}, timeout=_STILL_WAITING_INTERVAL)
                if task in done:
                    break
                waited += _STILL_WAITING_INTERVAL
                yield Event("llm_still_waiting", {"elapsed_seconds": waited})
        except asyncio.CancelledError:
            task.cancel()
            raise
        try:
            yield Event("llm_result", {"response": task.result()})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — handed to the caller, not raised here
            yield Event("llm_result", {"error": exc})

    async def _manage_context(self, tool_schemas: list[dict[str, Any]]) -> AsyncIterator[Event]:
        """Keep the running prompt under the model's real context window.

        History grows every turn as tool results accumulate, and the tool-schema
        list rides in every request alongside it, so both count toward the window.
        When the estimated prompt crosses the budget's compaction threshold,
        summarize the oldest WHOLE turns into one rolling checkpoint and keep the
        recent tail verbatim. This is non-destructive: the full record (stdout +
        typed findings) lives in durable memory, so a summarized turn loses nothing
        the model can't retrieve on demand via platform_artifact / platform_findings.
        """
        budget = self._ensure_budget()
        schema_tokens = estimate_tokens("".join(str(s) for s in tool_schemas))
        prompt_tokens = count_message_tokens(self.config.model, self.messages) + schema_tokens
        if prompt_tokens < budget.compact_at:
            return
        before = len(self.messages)
        yield Event("status", {"stage": "compacting", "message": "Refreshing conversation context from earlier progress…"})
        if await self._compact_now():
            yield Event(
                "compaction",
                {
                    "context_tokens": prompt_tokens,
                    "context_limit": budget.context_limit,
                    "messages_before": before,
                    "messages_after": len(self.messages),
                },
            )

    async def _compact_now(self) -> bool:
        """Summarize the oldest whole-turns into the rolling checkpoint and drop
        them from the live window. Returns True if history was actually compacted.

        If summarization fails, retain the original history so objectives and
        evidence are never silently discarded. Never splits a tool-call/result pair (plan_compaction
        cuts only on whole-turn boundaries) and never touches the system prompt."""
        budget = self._ensure_budget()
        plan = plan_compaction(self.config.model, self.messages, budget)
        if not plan.has_head:
            return False  # nothing old enough to summarize yet
        summary = ""
        try:
            resp = await complete(
                config=self.config,
                messages=build_summary_request(plan.head, previous_summary=self._running_summary),
                tools=None,
                max_tokens=1500,
            )
            summary = (resp["choices"][0]["message"].get("content") or "").strip()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — summarization is best-effort; never fatal
            summary = ""
        if summary:
            self._running_summary = summary
        else:
            return False
        checkpoint = [checkpoint_message(self._running_summary)] if self._running_summary else []
        self.messages = plan.system + checkpoint + plan.tail
        return True
