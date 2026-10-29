"""The single agent reasoning loop, split into setup/run mixins + helpers.

Runner composes the mixins; the public surface (Runner, Event, the module
helpers like tool_result_failed/refresh_system_message, and the tool
schemas) is unchanged for callers of agent_core.loop."""

from __future__ import annotations
from collections.abc import Awaitable, Callable
from typing import Any
from agent_core import tools as platform_tools
from agent_core.compaction import ContextBudget
from agent_core.llm import CLIModelConfig

from agent_core.loop._helpers import (
    _MAX_TURNS,
    _MAX_CONCURRENT_TOOLS,
    _COMPLETION_MAX_TOKENS,
    _STILL_WAITING_INTERVAL,
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
    _SPAWN_TOOL_SCHEMA,
    _ASK_TOOL_NAME,
    _ASK_TOOL_SCHEMA,
    Event,
    _normalize_options,
    _tag_worker_event,
)
from agent_core.loop._setup import _SetupMixin
from agent_core.loop._run import _RunMixin


class Runner(_SetupMixin, _RunMixin):
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
        # Explicit jobs keep a bounded budget. None uses the default; zero lets
        # an interactive session run until completion or operator cancellation.
        self._max_turns = _MAX_TURNS if max_turns is None else max_turns
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


__all__ = [
    "Runner",
    "_MAX_TURNS",
    "_MAX_CONCURRENT_TOOLS",
    "_COMPLETION_MAX_TOKENS",
    "_STILL_WAITING_INTERVAL",
    "_is_context_overflow",
    "_STALL_THRESHOLD",
    "_REPEATED_FAILURE_THRESHOLD",
    "_call_signature",
    "_result_fingerprint",
    "tool_result_failed",
    "refresh_system_message",
    "_stall_notice",
    "_repeated_failure_notice",
    "_SPAWN_TOOL_NAME",
    "_SPAWN_TOOL_SCHEMA",
    "_ASK_TOOL_NAME",
    "_ASK_TOOL_SCHEMA",
    "Event",
    "_normalize_options",
    "_tag_worker_event",
]
