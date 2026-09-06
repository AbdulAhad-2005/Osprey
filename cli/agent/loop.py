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
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from cli.agent import tools as platform_tools
from cli.agent.llm import CLIModelConfig, complete, friendly_llm_error

_MAX_TURNS = 30
_MAX_CONCURRENT_TOOLS = 4

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

    def __init__(self, *, config: CLIModelConfig, api_base_url: str, allow_spawn: bool = True) -> None:
        self.config = config
        self.messages: list[dict[str, Any]] = []
        self._allow_spawn = allow_spawn
        platform_tools.load_server(api_base_url)
        self._api_base_url = api_base_url

    def reset(self) -> None:
        self.messages = []

    def _tool_schemas(self) -> list[dict[str, Any]]:
        schemas = platform_tools.get_tool_schemas()
        if self._allow_spawn:
            schemas.append(_SPAWN_TOOL_SCHEMA)
        return schemas

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
                try:
                    response = await complete(
                        config=self.config, messages=self.messages, tools=tool_schemas
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — a failed model call
                    # ends this turn cleanly, it must never crash the session.
                    # Yields both "error" (the interactive CLI renders this)
                    # and "done" (a spawned worker's caller only ever reads
                    # "done" for its result) so neither consumer is left with
                    # nothing to show for the failure.
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

                async def _run_one(tc: dict[str, Any]) -> tuple[str, str, float]:
                    name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"].get("arguments") or "{}")
                    except (json.JSONDecodeError, ValueError):
                        args = {}
                    started = time.monotonic()
                    async with sem:
                        result = await self._dispatch_tool(name, args)
                    return name, result, time.monotonic() - started

                for tc in tool_calls:
                    yield Event(
                        "tool_start",
                        {"tool_name": tc["function"]["name"], "arguments": tc["function"].get("arguments", "{}")},
                    )

                results = await asyncio.gather(*(_run_one(tc) for tc in tool_calls))

                for tc, (name, result, elapsed) in zip(tool_calls, results):
                    yield Event(
                        "tool_end",
                        {"tool_name": name, "result": result, "duration_seconds": elapsed},
                    )
                    self.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": result[:12000],
                        }
                    )

            yield Event("done", {"content": "(stopped: reached the turn limit for this prompt)"})
        except asyncio.CancelledError:
            findings_readback = await platform_tools.call_tool(
                "platform_findings", {"engagement_id": platform_tools.current_engagement_id()}
            )
            yield Event("cancelled", {"findings": findings_readback})
            raise

    async def _dispatch_tool(self, name: str, args: dict[str, Any]) -> str:
        if name == _SPAWN_TOOL_NAME:
            return await self._spawn_subagents(args.get("tasks") or [])
        return await platform_tools.call_tool(name, args)

    async def _spawn_subagents(self, tasks: list[dict[str, Any]]) -> str:
        """Real concurrent subagent execution, in-process, using this same
        CLI's own model — no backend LLM key, no second brain. Depth is
        capped at 1: a spawned worker doesn't get the spawn tool itself, so
        this can't recurse into a fork bomb."""
        tasks = tasks[:_MAX_CONCURRENT_TOOLS]
        if len(tasks) < 2:
            return (
                "spawn_subagents needs 2+ genuinely independent tasks — for one "
                "line of work, just keep going in this turn instead."
            )

        engagement_id = platform_tools.current_engagement_id()

        async def _one(task: dict[str, Any]) -> str:
            worker = Runner(config=self.config, api_base_url=self._api_base_url, allow_spawn=False)
            scope = task.get("scope", "")
            brief = task.get("task", "")
            prompt = f"{brief}\n\n(engagement_id={engagement_id}" + (f", scope={scope})" if scope else ")")
            final = ""
            async for event in worker.run(prompt):
                if event.type == "done":
                    final = event.data.get("content", "")
            return final

        summaries = await asyncio.gather(*(_one(t) for t in tasks))
        parts = [f"Worker {i + 1} ({t.get('scope') or t.get('task', '')[:40]}):\n{s}" for i, (t, s) in enumerate(zip(tasks, summaries))]
        return "\n\n---\n\n".join(parts)
