"""The CLI's own ReAct loop — this is what makes the CLI a real agent host
instead of a remote control.

Shape mirrors the backend's proven `phase_agent.py` loop (build messages,
call the model, run any tool calls — concurrently, bounded — append results,
repeat until the model stops asking for tools) but is a new, small,
CLI-owned implementation: it only needs `tools.py` (HTTP-only, works
against a local or remote backend) and `llm.py` (a plain third-party
library), never the backend's own DB/job-store-coupled internals.

One `Runner` instance lives for the whole CLI session, so a follow-up
prompt sees the full prior conversation — exactly like Claude Code's own
CLI, not a one-shot request/response.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

from cli.agent import tools as platform_tools
from cli.agent.compaction import (
    ContextBudget,
    build_budget,
    build_summary_request,
    checkpoint_message,
    count_message_tokens,
    estimate_tokens,
    plan_compaction,
    spill_tool_result,
)
from cli.agent.llm import CLIModelConfig, complete, friendly_llm_error

_MAX_TURNS = 30
_MAX_CONCURRENT_TOOLS = 4
# Output tokens requested per completion — kept in sync with the budget's output
# reserve (compaction.resolve_output_reserve) so we compact before the provider
# would reject the request.
_COMPLETION_MAX_TOKENS = 4096


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
        allow_spawn: bool = True,
        tool_filter: "Callable[[str], bool] | None" = None,
    ) -> None:
        self.config = config
        self.messages: list[dict[str, Any]] = []
        self._allow_spawn = allow_spawn
        # Optional active-mode tool scope (from a prompt-defined agent/flow). None
        # = full catalog. Applied to what the model SEES and enforced on dispatch,
        # and inherited by spawned workers so a mode is consistent end to end.
        self._tool_filter = tool_filter
        platform_tools.load_server(api_base_url)
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
        schemas = platform_tools.get_tool_schemas(
            budget_tokens=self.config.tool_schema_budget_tokens
        )
        if self._tool_filter is not None:
            schemas = [s for s in schemas if self._tool_filter(s["function"]["name"])]
        if self._allow_spawn:
            schemas.append(_SPAWN_TOOL_SCHEMA)
        return schemas

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
        this loop finishing)."""
        if system_prompt and not any(m.get("role") == "system" for m in self.messages):
            self.messages.insert(0, {"role": "system", "content": system_prompt})
        self.messages.append({"role": "user", "content": prompt})

        tool_schemas = self._tool_schemas()

        try:
            for _turn in range(_MAX_TURNS):
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
                # (seconds, sometimes 10+ with the retry-with-backoff in
                # complete()) previously had zero visible feedback. The
                # renderer is responsible for turning this into a spinner and
                # clearing it on whatever event comes next — this loop stays
                # UI-agnostic, same as every other Event here.
                yield Event("llm_call_start", {})
                response = None
                try:
                    response = await complete(
                        config=self.config, messages=self.messages,
                        tools=tool_schemas, max_tokens=_COMPLETION_MAX_TOKENS,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — a failed model call
                    # A context-overflow is the ONE failure a retry can fix:
                    # force a compaction and try once more. Previously this ended
                    # the turn with "(stopped: ...)" — a long engagement simply
                    # died at the window instead of shedding old context. Every
                    # other failure still ends the turn cleanly (never crashes the
                    # session): "error" for the interactive CLI, "done" for a
                    # spawned worker's caller — so neither is left with nothing.
                    if _is_context_overflow(exc) and await self._compact_now():
                        yield Event("compaction", {"forced": True, "messages_after": len(self.messages)})
                        try:
                            response = await complete(
                                config=self.config, messages=self.messages,
                                tools=tool_schemas, max_tokens=_COMPLETION_MAX_TOKENS,
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc2:  # noqa: BLE001
                            exc = exc2
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
                        return name, _stall_notice(name, seen[1]), time.monotonic() - started
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
                    return name, result, time.monotonic() - started

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
                while True:
                    done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                    if get_task in done:
                        yield get_task.result()
                        get_task = asyncio.ensure_future(event_queue.get())
                        pending.add(get_task)
                    if gather_task in done:
                        get_task.cancel()
                        results = gather_task.result()
                        break
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
                engagement_id = platform_tools.current_engagement_id()
                for tc, (name, result, elapsed) in zip(tool_calls, results):
                    yield Event(
                        "tool_end",
                        {
                            "tool_name": name,
                            "result": result,
                            "duration_seconds": elapsed,
                            "tool_call_id": tc["id"],
                            "success": not tool_result_failed(result),
                        },
                    )
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
            findings_readback = await platform_tools.call_tool(
                "platform_findings", {"engagement_id": platform_tools.current_engagement_id()}
            )
            yield Event("cancelled", {"findings": findings_readback})
            raise

    async def _dispatch_tool(
        self, name: str, args: dict[str, Any], *, event_queue: "asyncio.Queue[Event] | None" = None
    ) -> str:
        if name == _SPAWN_TOOL_NAME:
            return await self._spawn_subagents(args.get("tasks") or [], event_queue=event_queue)
        # Enforce the active mode's tool scope even if the model names a tool that
        # wasn't advertised — advertising-only scoping isn't real enforcement.
        if self._tool_filter is not None and not self._tool_filter(name):
            return (
                f"BLOCKED (mode restriction): '{name}' is not available in the current mode. "
                "Use a tool this mode allows, or switch mode with /agent."
            )
        return await platform_tools.call_tool(name, args)

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

        engagement_id = platform_tools.current_engagement_id()

        async def _one(worker_num: int, task: dict[str, Any]) -> str:
            worker = Runner(
                config=self.config, api_base_url=self._api_base_url,
                allow_spawn=False, tool_filter=self._tool_filter,
            )
            scope = task.get("scope", "")
            brief = task.get("task", "")
            prompt = f"{brief}\n\n(engagement_id={engagement_id}" + (f", scope={scope})" if scope else ")")
            final = ""
            async for event in worker.run(prompt):
                if event.type == "done":
                    final = event.data.get("content", "")
                elif event_queue is not None and event.type in ("thinking", "tool_start", "tool_end", "error"):
                    await event_queue.put(_tag_worker_event(worker_num, event))
            return final

        summaries = await asyncio.gather(*(_one(i + 1, t) for i, t in enumerate(tasks)))
        parts = [f"Worker {i + 1} ({t.get('scope') or t.get('task', '')[:40]}):\n{s}" for i, (t, s) in enumerate(zip(tasks, summaries))]
        return "\n\n---\n\n".join(parts)


def _tag_worker_event(worker_num: int, event: Event) -> Event:
    """Copy a spawned worker's event with its origin marked, so the render
    layer (and the operator) can tell "Worker 2 is running nmap" apart from
    the parent loop's own tool calls without changing what either renderer
    already keys off of (tool_name / content)."""
    data = dict(event.data)
    if "tool_name" in data:
        data["tool_name"] = f"[Worker {worker_num}] {data['tool_name']}"
    if "content" in data:
        data["content"] = f"[Worker {worker_num}] {data['content']}"
    if "message" in data:
        data["message"] = f"[Worker {worker_num}] {data['message']}"
    return Event(event.type, data)
