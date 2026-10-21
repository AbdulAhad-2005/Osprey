"""The CLI's own ReAct loop — this is what makes the CLI a real agent host
instead of a remote control.

This is the ONE reasoning loop in Osprey: build messages, call the model, run
any tool calls — concurrently, bounded — append results, repeat until the model
stops asking for tools. The CLI drives it directly, and the backend runs a
headless instance of this same `Runner` for every scoped sub-agent job
(services/agent_runner.py) — there is no separate backend-native agent loop.
It needs only `tools.py` (HTTP-only, works against a local or remote backend)
and `llm.py` (a plain third-party library), never a DB/job-store-coupled path.

One `Runner` instance lives for the whole CLI session, so a follow-up
prompt sees the full prior conversation — exactly like Claude Code's own
CLI, not a one-shot request/response.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from agent_core import tools as platform_tools
from agent_core.compaction import (
    ContextBudget,
    build_budget,
    build_summary_request,
    checkpoint_message,
    count_message_tokens,
    estimate_tokens,
    plan_compaction,
    spill_tool_result,
)
from agent_core.llm import CLIModelConfig, complete, friendly_llm_error

_MAX_TURNS = 30
_MAX_CONCURRENT_TOOLS = 4
# Output tokens requested per completion — kept in sync with the budget's output
# reserve (compaction.resolve_output_reserve) so we compact before the provider
# would reject the request.
_COMPLETION_MAX_TOKENS = 4096
# How often to report "still waiting on the provider" while a completion call
# is in flight — a genuinely overloaded provider can take several minutes
# (complete()'s own 3-attempt x up to 120s retry) to finally fail; without a
# periodic signal that's indistinguishable from a hang. See _complete_with_feedback.
_STILL_WAITING_INTERVAL = 15.0


def _is_context_overflow(exc: Exception) -> bool:
    """True when a completion failed specifically because the request exceeded the
    model's context window — the one failure a compaction-and-retry can fix."""
    try:
        import litellm

        if isinstance(exc, litellm.ContextWindowExceededError):
            return True
    except Exception:  # noqa: BLE001 — litellm import/attr issues never matter here
        pass
    text = str(exc).lower()
    return any(
        s in text
        for s in ("context length", "maximum context", "context_length_exceeded",
                  "too many tokens", "reduce the length", "context window")
    )


# --- Loop-level failure/repeat guards ------------------------------------
# Per-call recovery (param adjust, tool switch, escalation-matrix auto-fallback)
# already happens server-side inside one tool call. What the AGENT LOOP must add
# is cross-call escalation: an LLM stuck re-issuing a call that makes no progress,
# or hammering a tool that keeps failing, across turns. Neither is caught below
# the loop — this is where "escalate on repeated failure" lives.
#
# The guard keys on NON-PROGRESS (same call → same result), not merely on "same
# arguments": a poll (platform_job_poll, a platform_context refresh) is SUPPOSED
# to be called repeatedly with identical args, and its result changes as state
# advances — so it must never be blocked. Only a call whose result stops changing
# (a stuck poll, a deterministic scan re-run for no reason, a repeating failure)
# trips the guard. No tool allowlist, no special-casing — the signal is the data.
_STALL_THRESHOLD = 3           # identical (call → identical result) repeats before the next is blocked
_REPEATED_FAILURE_THRESHOLD = 3  # consecutive failures of one tool before a "stop retrying it" nudge


def _call_signature(name: str, args: dict[str, Any]) -> str:
    try:
        return name + ":" + json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return name + ":" + str(sorted((args or {}).items()))


def _result_fingerprint(result: str) -> str:
    """Cheap, stable identity of a tool result, so repeated-but-changing output
    (a poll advancing) is distinguished from genuinely non-progressing output."""
    import hashlib

    return hashlib.sha1(result.encode("utf-8", "replace")).hexdigest()


def tool_result_failed(result: str) -> bool:
    """Canonical failure signal for a tool result — the platform's own
    ``success: False`` line, or a dispatch-level ``ERROR ...`` string. Single
    source of truth shared by the loop's failure escalation and the CLI renderer
    (cli/commands/prompt.py), so the two can't drift on what 'failed' means."""
    if result.lstrip().startswith("ERROR"):
        return True
    import re

    m = re.search(r"(?im)^success:\s*(true|false)\b", result)
    return bool(m) and m.group(1).lower() == "false"


def refresh_system_message(messages: list[dict[str, Any]], system_prompt: str) -> list[dict[str, Any]]:
    """Replace the current system message with a fresh one, or insert it if
    there isn't one yet — plans/harness/07-context-packet.md Step 2/4. A pure
    function (no I/O) so the "rebuild every turn, including across
    compaction" behavior is directly testable without mocking the LLM/tool
    machinery ``Runner.run()`` also needs. Mutates and returns ``messages``
    for convenience; empty ``system_prompt`` is a no-op (keeps whatever's
    already there unchanged)."""
    if not system_prompt:
        return messages
    fresh = {"role": "system", "content": system_prompt}
    if messages and messages[0].get("role") == "system":
        messages[0] = fresh
    else:
        messages.insert(0, fresh)
    return messages


def _stall_notice(name: str, count: int) -> str:
    return (
        f"BLOCKED (no-progress guard): {name} returned the same result {count} times "
        f"in a row for this input — re-running it is not advancing the engagement. "
        f"Change the arguments or approach, try a different tool, or record this as a "
        f"blocker and move on — do not repeat this exact call."
    )


def _repeated_failure_notice(name: str, count: int) -> str:
    return (
        f"\n\n[loop guard] {name} has now failed {count} times in a row. Stop "
        f"retrying it as-is — switch to an alternative tool (see any hints in the "
        f"output above) or a different technique, or report the blocker and move on."
    )

# CLI-native — not a platform tool. This is the actual fix for "spawns a
# subagent for everything": it's a real, capped tool the model has to
# deliberately reach for, with an explicit policy in its own description,
# not just advisory prompt text elsewhere that only some harnesses read.
_SPAWN_TOOL_NAME = "spawn_subagents"
_SPAWN_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": _SPAWN_TOOL_NAME,
        "description": (
            "Run 2-4 genuinely independent, parallelizable slices of work at "
            "once (e.g. one sister domain each, one unrelated host each, one "
            "candidate each) as separate concurrent workers sharing this "
            "engagement's memory. Each worker gets its own tools and reports "
            "back a short summary when done. "
            "Do NOT call this for a single line of work, for sequential steps "
            "that depend on each other, or just because a task 'sounds big' — "
            "keep working in the current turn instead. Only call this when you "
            "can name 2 or more slices that could genuinely run at the same "
            "time with no dependency between them."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": _MAX_CONCURRENT_TOOLS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "task": {
                                "type": "string",
                                "description": "The independent slice of work for this worker, in full — it has no other context.",
                            },
                            "scope": {
                                "type": "string",
                                "description": "The specific target/host/domain this worker is scoped to.",
                            },
                        },
                        "required": ["task"],
                    },
                }
            },
            "required": ["tasks"],
        },
    },
}


# CLI/transport-native — not a platform tool. Lets the model pause the run to
# put a bounded decision to the operator (an exploitation gate, a scope choice)
# with proposed answers, instead of guessing or stopping. Only advertised when
# a caller injects an `ask_handler` (the GUI/CLI foreground loop); a headless
# sub-agent or an unattended run never sees it, so it can't block on a human
# who isn't there.
_ASK_TOOL_NAME = "ask_operator"
_ASK_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": _ASK_TOOL_NAME,
        "description": (
            "Pause and ask the human operator a single, consequential decision "
            "that changes what you do next — e.g. whether to cross from findings "
            "into active exploitation, whether to pull in a newly-discovered "
            "root/sister domain as in-scope, or which of two materially different "
            "paths to take. The run blocks until they answer, then you continue "
            "with their decision. Do NOT use this for trivia, for progress "
            "updates, or to ask permission for an ordinary next tool call — only "
            "for a real fork that needs a human's call. Offer 2-4 concrete "
            "options."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The decision to put to the operator, in one or two sentences.",
                },
                "options": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string", "description": "Short machine value, e.g. 'proceed'."},
                            "label": {"type": "string", "description": "Button text the operator sees."},
                            "detail": {"type": "string", "description": "Optional one-line consequence of this choice."},
                            "intent": {
                                "type": "string",
                                "enum": ["default", "primary", "danger"],
                                "description": "Visual weight; use 'danger' for an exploitation/destructive go.",
                            },
                        },
                        "required": ["value", "label"],
                    },
                },
                "kind": {
                    "type": "string",
                    "enum": ["gate", "scope", "choice"],
                    "description": "'gate' for an exploitation/destructive gate, 'scope' for a scope-expansion decision, else 'choice'.",
                },
                "allow_freeform": {
                    "type": "boolean",
                    "description": "Allow the operator to type a custom answer in addition to the options.",
                },
            },
            "required": ["question", "options"],
        },
    },
}


@dataclass
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)


class Runner:
    """One agent session. Persists `messages` across `run()` calls so
    follow-up prompts have full context, same as Claude Code's own CLI."""

    def __init__(
        self,
        *,
        config: CLIModelConfig,
        api_base_url: str,
        engagement_id: str = "",
        target: str = "",
        allow_spawn: bool = True,
        tool_filter: "Callable[[str], bool] | None" = None,
        agent_prompt: str = "",
        tool_gateway: "platform_tools.EmbeddedToolGateway | None" = None,
        worker_factory: "Callable[..., Runner] | None" = None,
        ask_handler: "Callable[[dict[str, Any]], Awaitable[str]] | None" = None,
        max_turns: int | None = None,
    ) -> None:
        self.config = config
        self.messages: list[dict[str, Any]] = []
        self._allow_spawn = allow_spawn
        # Per-instance turn cap (e.g. a job's requested max_turns). None/0 keeps
        # the module default — every existing caller (interactive CLI, workers)
        # is unaffected since none of them pass this.
        self._max_turns = max_turns or _MAX_TURNS
        # Optional active-mode tool scope (from a prompt-defined agent/flow). None
        # = full catalog. Applied to what the model SEES and enforced on dispatch,
        # and inherited by spawned workers so a mode is consistent end to end.
        self._tool_filter = tool_filter
        self._tool_gateway = tool_gateway or platform_tools.EmbeddedToolGateway(api_base_url)
        self._worker_factory = worker_factory
        # When set, the model is offered the `ask_operator` tool and this async
        # callback is awaited to obtain the operator's answer. None (the default,
        # for the CLI and all headless sub-agents) means the tool is never
        # advertised, so nothing can block on an absent human.
        self._ask_handler = ask_handler
        self._engagement_id = (engagement_id or "").strip()
        self._target = (target or "").strip()
        self._agent_prompt = agent_prompt
        if self._engagement_id:
            self._tool_gateway.bind(engagement_id=self._engagement_id, target=self._target)
        self._api_base_url = api_base_url
        # Context management (budget resolved lazily on first use — needs the
        # model's real context window from litellm). The rolling checkpoint is
        # the compacted memory of turns dropped from the live window.
        self._budget: ContextBudget | None = None
        self._running_summary: str = ""
        # Loop guards (session-scoped). Stall guard tracks, per call signature,
        # (last_result_fingerprint, consecutive_identical_count) to detect
        # non-progress. Failure guard tracks consecutive failures per tool.
        self._call_outcomes: dict[str, tuple[str, int]] = {}
        self._failure_counts: dict[str, int] = {}

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

        If the summarization call itself fails, still drop the old turns but keep
        the prior checkpoint — the session survives a provider hiccup, and findings
        stay durable regardless. Never splits a tool-call/result pair (plan_compaction
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
        checkpoint = [checkpoint_message(self._running_summary)] if self._running_summary else []
        self.messages = plan.system + checkpoint + plan.tail
        return True

    async def run(self, prompt: str, *, system_prompt: str = "") -> AsyncIterator[Event]:
        """The loop. Yields events for the caller to render. Safe to wrap in
        an `asyncio.Task` and `.cancel()` — on cancellation this reads back
        what the engagement already has before the CancelledError propagates,
        since tool-call findings are already durably saved server-side by the
        time a tool call returns (nothing about that persistence depends on
        this loop finishing).

        ``system_prompt``, when given, REPLACES the current system message
        rather than only being inserted the first time (plans/harness/07-
        context-packet.md Step 2: the context packet is rebuilt from the
        world model on every turn, not just the first — a caller that wants
        it kept fresh passes a newly-built one on every call; the caller
        decides how often to rebuild, this method only ever applies whatever
        it's given). A caller that passes nothing keeps whatever system
        message already exists, unchanged."""
        refresh_system_message(self.messages, system_prompt)
        self.messages.append({"role": "user", "content": prompt})

        tool_schemas = self._tool_schemas()

        try:
            for _turn in range(self._max_turns):
                # History grows every turn as tool results accumulate and rides
                # in every request alongside the tool schema list. Keep it under
                # the model's real context window before each call — summarizing
                # the oldest turns when needed, non-destructively. Re-checked
                # every iteration, not just once at the top of run(): a session
                # that fit fine on turn 1 can still run over by turn 3.
                async for _ctx_event in self._manage_context(tool_schemas):
                    yield _ctx_event
                # Signals the start of the one genuinely silent gap in this
                # loop — everything else (tool calls, worker sub-events) has
                # its own start/end events already; the model call itself
                # previously had zero visible feedback beyond a static spinner,
                # which is indistinguishable from a real hang once a slow/
                # overloaded provider's own retry-with-backoff (complete()'s
                # 3 attempts x up to 120s each) stretches past a few minutes —
                # confirmed live during QA: a genuinely overloaded provider
                # produced ~6 minutes of total silence, easily mistaken for a
                # hung CLI. _complete_with_feedback yields periodic
                # "llm_still_waiting" events during that wait so the renderer
                # can show elapsed time instead of one unchanging spinner.
                yield Event("llm_call_start", {})
                response = None
                exc: Exception | None = None
                async for ev in self._complete_with_feedback(tool_schemas):
                    if ev.type == "llm_result":
                        response, exc = ev.data.get("response"), ev.data.get("error")
                    else:
                        yield ev
                if exc is not None:
                    if isinstance(exc, asyncio.CancelledError):
                        raise exc
                    # A context-overflow is the ONE failure a retry can fix:
                    # force a compaction and try once more. Previously this ended
                    # the turn with "(stopped: ...)" — a long engagement simply
                    # died at the window instead of shedding old context. Every
                    # other failure still ends the turn cleanly (never crashes the
                    # session): "error" for the interactive CLI, "done" for a
                    # spawned worker's caller — so neither is left with nothing.
                    if _is_context_overflow(exc) and await self._compact_now():
                        yield Event("compaction", {"forced": True, "messages_after": len(self.messages)})
                        async for ev in self._complete_with_feedback(tool_schemas):
                            if ev.type == "llm_result":
                                response, exc = ev.data.get("response"), ev.data.get("error")
                            else:
                                yield ev
                        if isinstance(exc, asyncio.CancelledError):
                            raise exc
                    if response is None:
                        msg = friendly_llm_error(exc)
                        yield Event("error", {"message": msg})
                        yield Event("done", {"content": f"(stopped: {msg})"})
                        return
                message = response["choices"][0]["message"]
                tool_calls = message.get("tool_calls") or []

                if not tool_calls:
                    content = message.get("content") or ""
                    self.messages.append({"role": "assistant", "content": content})
                    yield Event("assistant_text", {"content": content})
                    yield Event("done", {"content": content})
                    return

                inline_text = (message.get("content") or "").strip()
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": message.get("content") or "",
                        "tool_calls": tool_calls,
                    }
                )
                if inline_text:
                    # The model's own reasoning for what it's about to do —
                    # previously appended to history but never rendered, so
                    # every intermediate turn looked like tool calls firing
                    # with no explanation until the final answer.
                    yield Event("thinking", {"content": inline_text})

                sem = asyncio.Semaphore(_MAX_CONCURRENT_TOOLS)
                # Sub-events a spawned worker produces (its own tool calls,
                # reasoning) are pushed here as they happen and drained into
                # this generator's own output below — the fix for
                # spawn_subagents being a single opaque tool_start/tool_end
                # pair that blocks for minutes with zero visibility into what
                # its workers are actually doing. See _spawn_subagents.
                event_queue: asyncio.Queue[Event] = asyncio.Queue()

                async def _run_one(tc: dict[str, Any]) -> tuple[str, str, float]:
                    name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"].get("arguments") or "{}")
                    except (json.JSONDecodeError, ValueError):
                        args = {}
                    started = time.monotonic()
                    # No-progress guard: block the next call ONLY once this exact
                    # call has already returned the SAME result _STALL_THRESHOLD
                    # times running. A poll whose result changes as state advances
                    # resets the counter and is never blocked — the signal is
                    # non-progress, not merely "same arguments".
                    sig = _call_signature(name, args)
                    seen = self._call_outcomes.get(sig)
                    if seen and seen[1] >= _STALL_THRESHOLD:
                        result = _stall_notice(name, seen[1])
                        elapsed = time.monotonic() - started
                        event_queue.put_nowait(Event("tool_end", {
                            "tool_name": name, "result": result, "duration_seconds": elapsed,
                            "tool_call_id": tc["id"], "success": not tool_result_failed(result),
                        }))
                        return name, result, elapsed
                    async with sem:
                        result = await self._dispatch_tool(name, args, event_queue=event_queue)
                    fp = _result_fingerprint(result)
                    if seen and seen[0] == fp:
                        self._call_outcomes[sig] = (fp, seen[1] + 1)
                    else:
                        self._call_outcomes[sig] = (fp, 1)
                    # Repeated-failure escalation: after N consecutive failures of
                    # one tool, append a "stop retrying it" nudge (the failed result
                    # already carries alternative-tool hints from the backend). A
                    # success resets the streak.
                    if tool_result_failed(result):
                        self._failure_counts[name] = self._failure_counts.get(name, 0) + 1
                        if self._failure_counts[name] >= _REPEATED_FAILURE_THRESHOLD:
                            result += _repeated_failure_notice(name, self._failure_counts[name])
                    else:
                        self._failure_counts[name] = 0
                    elapsed = time.monotonic() - started
                    event_queue.put_nowait(Event("tool_end", {
                        "tool_name": name, "result": result,
                        "duration_seconds": elapsed, "tool_call_id": tc["id"],
                        "success": not tool_result_failed(result),
                    }))
                    return name, result, elapsed

                for tc in tool_calls:
                    yield Event(
                        "tool_start",
                        {
                            "tool_name": tc["function"]["name"],
                            "arguments": tc["function"].get("arguments", "{}"),
                            "tool_call_id": tc["id"],
                        },
                    )

                gather_task: asyncio.Task[list[tuple[str, str, float]]] = asyncio.ensure_future(
                    asyncio.gather(*(_run_one(tc) for tc in tool_calls))
                )
                get_task: asyncio.Task[Event] = asyncio.ensure_future(event_queue.get())
                pending = {gather_task, get_task}
                try:
                    while True:
                        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                        if get_task in done:
                            yield get_task.result()
                            get_task = asyncio.ensure_future(event_queue.get())
                            pending.add(get_task)
                        if gather_task in done:
                            results = gather_task.result()
                            break
                finally:
                    get_task.cancel()
                    if not gather_task.done():
                        gather_task.cancel()
                    await asyncio.gather(get_task, gather_task, return_exceptions=True)
                # A sub-event can land in the queue in the instant between the
                # gather finishing and the cancel above taking effect.
                while not event_queue.empty():
                    yield event_queue.get_nowait()

                # `result` here already went through the backend's ONE stdout
                # policy (osprey.services.output_budget, applied in
                # execute_tool_request before this ever reaches the CLI) — do
                # not re-cap it a second time by default, or a high-value
                # tool's budgeted dump (e.g. a sqlmap table list) gets
                # silently shrunk right back down for CLI users specifically.
                #
                # Tool results accumulate in self.messages for the rest of the
                # session (every later turn resends the full history). On an
                # unconstrained provider, keep the server's result as-is. On a
                # token-per-minute-budgeted one, history is the OTHER thing
                # (besides the tool schema list) competing for the same
                # per-minute cap, and it grows every turn while the schema
                # list doesn't — a session that started fine can still run
                # into the ceiling a few tool calls later, so THAT mode keeps
                # a smaller history-retention cap (a distinct budget from "how
                # much to show now" — see output_budget.history_result_cap()
                # in the backend, which this mirrors; the CLI can't import the
                # backend package directly since it may talk to a remote one,
                # so keep this constant in sync with that function by hand).
                _CLI_HISTORY_CAP_CHARS = 3000
                cap_history = self.config.tool_schema_budget_tokens > 0
                engagement_id = self._engagement_id or self._tool_gateway.engagement_id
                for tc, (name, result, elapsed) in zip(tool_calls, results):
                    # Non-budgeted providers keep the server's already-budgeted
                    # result verbatim (the backend's output_budget owns per-call
                    # size; cumulative growth is handled by _manage_context's
                    # compaction). A per-minute-budgeted provider additionally
                    # caps each result kept in history — but via SPILL (head/tail
                    # + a pointer to the durable copy), not a silent cut, so the
                    # model knows output was trimmed and how to retrieve it.
                    stored = (
                        spill_tool_result(result, engagement_id=engagement_id, max_chars=_CLI_HISTORY_CAP_CHARS)
                        if cap_history
                        else result
                    )
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": stored,
                        }
                    )

            yield Event("done", {"content": "(stopped: reached the turn limit for this prompt)"})
        except asyncio.CancelledError:
            # Keep provider tool-call/result pairing valid for the next prompt.
            # A stopped batch may have emitted visible results before the full
            # batch could be appended to model history.
            last_call = next((m for m in reversed(self.messages) if m.get("tool_calls")), None)
            answered = {m.get("tool_call_id") for m in self.messages if m.get("role") == "tool"}
            for call in (last_call or {}).get("tool_calls", []):
                if call["id"] not in answered:
                    self.messages.append({"role": "tool", "tool_call_id": call["id"],
                        "content": "Operator stopped the run before the batch returned to model history. Consult the durable tool transcript/artifacts for any completed output."})
            findings_readback = await self._tool_gateway.call(
                "platform_findings",
                {"engagement_id": self._engagement_id or self._tool_gateway.engagement_id},
            )
            yield Event("cancelled", {"findings": findings_readback})
            raise

    async def _dispatch_tool(
        self, name: str, args: dict[str, Any], *, event_queue: "asyncio.Queue[Event] | None" = None
    ) -> str:
        if name == _SPAWN_TOOL_NAME:
            return await self._spawn_subagents(args.get("tasks") or [], event_queue=event_queue)
        if name == _ASK_TOOL_NAME:
            return await self._ask_operator(args, event_queue=event_queue)
        # Enforce the active mode's tool scope even if the model names a tool that
        # wasn't advertised — advertising-only scoping isn't real enforcement.
        if self._tool_filter is not None and not self._tool_filter(name):
            return (
                f"BLOCKED (mode restriction): '{name}' is not available in the current mode. "
                "Use a tool this mode allows, or switch mode with /agent."
            )
        return await self._tool_gateway.call(name, args)

    async def _ask_operator(
        self, args: dict[str, Any], *, event_queue: "asyncio.Queue[Event] | None" = None
    ) -> str:
        """Put a bounded decision to the operator and block until they answer.

        Generates the question id here so the `question` event (streamed to the
        client) and the answer the caller's ``ask_handler`` resolves share one
        id — the client answers that id, the handler's Future completes, and
        this tool call returns the chosen answer into the ReAct loop. The
        handler is transport-owned (the GUI/CLI foreground loop injects it), so
        the loop itself stays backend-agnostic."""
        if self._ask_handler is None:  # defensive: tool not advertised without a handler
            return "ask_operator is unavailable in this run."
        question = (args.get("question") or "").strip()
        if not question:
            return "ask_operator requires a 'question'."
        options = _normalize_options(args.get("options") or [])
        if len(options) < 2:
            return "ask_operator requires 2-4 concrete options."
        import uuid

        record = {
            "id": uuid.uuid4().hex[:12],
            "text": question,
            "options": options,
            "kind": (args.get("kind") or "choice"),
            "allow_freeform": bool(args.get("allow_freeform", False)),
        }
        if event_queue is not None:
            await event_queue.put(Event("question", record))
        answer = await self._ask_handler(record)
        answer = (answer or "").strip() or "(no answer)"
        return (
            f"The operator answered: {answer!r}. Treat this as their decision and "
            f"continue accordingly — do not ask the same question again."
        )

    async def _worker_system_prompt(self, brief: str, scope: str, *, engagement_id: str = "") -> str:
        """A spawned worker's system prompt — plans/harness/08-skill-system-
        at-scale.md Step 4. Previously a spawned worker got no system prompt
        at all (a real gap, not a deliberate minimalism — it inherited zero
        policy and zero skills). Two independent fixes landed for this and
        both matter, so both are kept:

        - The same complete base policy, engagement briefing (full
          ``platform_context``), active-mode overlay, and tool-budget
          instructions the parent gets (``build_system_prompt``) — without
          this a worker doesn't know the spawn/record_findings/propose_skill
          rules, ignores an operator-defined custom mode, and is blind to a
          constrained tool-schema budget.
        - ON TOP of that, skills ranked against THIS worker's own brief+scope
          (mirrors Strix's child-agent specialization) — the context packet's
          own RELEVANT SKILLS section ranks against the engagement's overall
          top priorities, which can easily miss what one narrowly-scoped
          worker specifically needs while the top-level priority list is
          dominated by something else.
        """
        from agent_core.context import build_system_prompt

        base_prompt = await build_system_prompt(
            engagement_id,
            tool_budget_active=self.config.tool_schema_budget_tokens > 0,
            agent_prompt=self._agent_prompt,
            tool_caller=self._tool_gateway.call,
        )
        query = f"{brief} {scope}".strip()
        try:
            skills_text = await self._tool_gateway.call(
                "platform_skills", {"query": query, "limit": 5} if query else {}
            )
        except Exception:  # noqa: BLE001 — a skills-lookup failure must never block the worker
            skills_text = ""
        task_skills_block = (
            "\n---\n## SKILLS RANKED FOR YOUR SPECIFIC TASK\n"
            "(pull full text via platform_skills(path=...) if one looks useful)\n"
            + (skills_text or "(none matched — proceed on judgment)")
        )
        return base_prompt + task_skills_block

    async def _spawn_subagents(
        self, tasks: list[dict[str, Any]], *, event_queue: "asyncio.Queue[Event] | None" = None
    ) -> str:
        """Real concurrent subagent execution, in-process, using this same
        CLI's own model — no backend LLM key, no second brain. Depth is
        capped at 1: a spawned worker doesn't get the spawn tool itself, so
        this can't recurse into a fork bomb.

        Each worker's own thinking/tool_start/tool_end/error events are
        pushed onto ``event_queue`` (tagged "[Worker N]") as they happen, so
        the operator sees live progress instead of the whole call sitting
        silent for however long the slowest worker takes — previously this
        only ever surfaced the worker's final "done" text, discarding every
        intermediate event, which made a multi-minute spawn look hung.
        """
        tasks = tasks[:_MAX_CONCURRENT_TOOLS]
        if len(tasks) < 2:
            return (
                "spawn_subagents needs 2+ genuinely independent tasks — for one "
                "line of work, just keep going in this turn instead."
            )
        if self._worker_factory is None:
            return "spawn_subagents is unavailable: no harness worker manager is attached."

        engagement_id = self._engagement_id or self._tool_gateway.engagement_id

        async def _one(worker_num: int, task: dict[str, Any]) -> str:
            worker = self._worker_factory(
                config=self.config,
                engagement_id=engagement_id,
                target=self._target,
                tool_filter=self._tool_filter,
                agent_prompt=self._agent_prompt,
            )
            scope = task.get("scope", "")
            brief = task.get("task", "")
            prompt = f"{brief}\n\n(engagement_id={engagement_id}" + (f", scope={scope})" if scope else ")")
            system_prompt = await self._worker_system_prompt(brief, scope, engagement_id=engagement_id)
            final = ""
            async for event in worker.run(prompt, system_prompt=system_prompt):
                if event.type == "done":
                    final = event.data.get("content", "")
                elif event_queue is not None and event.type in ("thinking", "tool_start", "tool_end", "error"):
                    await event_queue.put(_tag_worker_event(worker_num, event))
            return final

        summaries = await asyncio.gather(*(_one(i + 1, t) for i, t in enumerate(tasks)))
        parts = [f"Worker {i + 1} ({t.get('scope') or t.get('task', '')[:40]}):\n{s}" for i, (t, s) in enumerate(zip(tasks, summaries))]
        return "\n\n---\n\n".join(parts)


def _normalize_options(raw: list[Any]) -> list[dict[str, Any]]:
    """Coerce model-supplied options into {value,label,detail?,intent?}, keeping
    only well-formed ones, capped at 4."""
    out: list[dict[str, Any]] = []
    for item in raw[:4]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or item.get("label") or "").strip()
        label = str(item.get("label") or item.get("value") or "").strip()
        if not value or not label:
            continue
        opt: dict[str, Any] = {"value": value, "label": label}
        detail = str(item.get("detail") or "").strip()
        if detail:
            opt["detail"] = detail
        intent = str(item.get("intent") or "").strip()
        if intent in ("default", "primary", "danger"):
            opt["intent"] = intent
        out.append(opt)
    return out


def _tag_worker_event(worker_num: int, event: Event) -> Event:
    """Copy a spawned worker's event with its origin marked, so the render
    layer (and the operator) can tell "Worker 2 is running nmap" apart from
    the parent loop's own tool calls without changing what either renderer
    already keys off of (tool_name / content)."""
    data = dict(event.data)
    data["source"] = f"worker-{worker_num}"
    if data.get("tool_call_id"):
        data["tool_call_id"] = f"worker-{worker_num}:{data['tool_call_id']}"
    if "tool_name" in data:
        data["tool_name"] = f"[Worker {worker_num}] {data['tool_name']}"
    if "content" in data:
        data["content"] = f"[Worker {worker_num}] {data['content']}"
    if "message" in data:
        data["message"] = f"[Worker {worker_num}] {data['message']}"
    return Event(event.type, data)
