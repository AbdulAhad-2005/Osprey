"""Runner main loop + tool-dispatch / operator / subagent methods (mixin)."""

from __future__ import annotations
import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any
from agent_core.compaction import (
    spill_tool_result,
)
from agent_core.llm import friendly_llm_error
from agent_core.loop._helpers import (
    _MAX_CONCURRENT_TOOLS,
    _is_context_overflow,
    _STALL_THRESHOLD,
    _REPEATED_FAILURE_THRESHOLD,
    _call_signature,
    _result_fingerprint,
    tool_result_failed,
    refresh_system_message,
    _stall_notice,
    _repeated_failure_notice,
    _SPAWN_TOOL_NAME,
    _ASK_TOOL_NAME,
    Event,
    _normalize_options,
    _tag_worker_event,
)


class _RunMixin:

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
        batch_results: dict[str, str] = {}

        try:
            _turn = 0
            empty_responses = 0
            while self._max_turns <= 0 or _turn < self._max_turns:
                _turn += 1
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
                        yield Event("done", {"content": f"(stopped: {msg})", "reason": "error"})
                        return
                message = response["choices"][0]["message"]
                finish_reason = response["choices"][0].get("finish_reason", "")
                tool_calls = message.get("tool_calls") or []

                if not tool_calls:
                    content = message.get("content") or ""
                    if not content.strip():
                        empty_responses += 1
                        if empty_responses == 1:
                            yield Event("status", {"stage": "retrying", "message": "The model returned an empty response. Retrying once…"})
                            continue
                        msg = ("The model exhausted its response limit without producing text or tool calls. "
                               if finish_reason == "length" else "The model returned no text or tool calls after a retry. ")
                        msg += "Resume to try again, or choose another model in Settings."
                        yield Event("error", {"message": msg})
                        yield Event("done", {"content": "", "reason": "empty_response", "finish_reason": finish_reason})
                        return
                    self.messages.append({"role": "assistant", "content": content})
                    yield Event("assistant_text", {"content": content})
                    yield Event("done", {"content": content, "reason": "completed", "finish_reason": finish_reason})
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
                batch_results = {}

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
                        batch_results[tc["id"]] = result
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
                    batch_results[tc["id"]] = result
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

            yield Event("done", {"content": "(paused: reached the turn limit for this prompt)", "reason": "turn_limit"})
        except asyncio.CancelledError:
            # Keep provider tool-call/result pairing valid for the next prompt.
            # A stopped batch may have emitted visible results before the full
            # batch could be appended to model history.
            last_call = next((m for m in reversed(self.messages) if m.get("tool_calls")), None)
            answered = {m.get("tool_call_id") for m in self.messages if m.get("role") == "tool"}
            for call in (last_call or {}).get("tool_calls", []):
                if call["id"] not in answered:
                    self.messages.append({"role": "tool", "tool_call_id": call["id"],
                        "content": batch_results.get(call["id"], "Operator paused before this result returned. Check durable jobs/artifacts before repeating the action.")})
            try:
                findings_readback = await asyncio.wait_for(self._tool_gateway.call(
                    "platform_findings", {"engagement_id": self._engagement_id or self._tool_gateway.engagement_id},
                ), timeout=5)
            except Exception:
                findings_readback = "Recorded evidence is retained in engagement memory."
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
