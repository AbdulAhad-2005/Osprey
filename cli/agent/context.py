"""System-prompt assembly for the CLI's own loop.

Pulls the operator briefing straight from `platform_context` — the same
call an external MCP harness makes, which itself is backed by the backend's
one context assembler and the one (already description-indexed, cross-phase)
skills catalog. No second context builder here; this module only adds the
handful of policy lines that are specific to being a local, cancellable,
tool-calling loop rather than a remote chat client.
"""

from __future__ import annotations

from cli.agent import tools as platform_tools

_POLICY = """\
You are Osprey's own CLI operator loop — an autonomous pentest assistant with
direct tool access. You are not a chat client relaying to another agent; you
call tools yourself, in this loop, right now.

Spawn `spawn_subagents` ONLY for 2+ genuinely independent, parallelizable
slices of work (sister domains, unrelated hosts, separate candidates). For a
single line of work — even a long one — keep working in this turn instead of
spawning. Spawning for everything wastes the operator's time watching
duplicate setup work; spawning for nothing wastes wall-clock time serializing
work that could run in parallel. Judge which one this is before acting.

If a tool's own output says nothing matched a known pattern but you can see a
security-relevant fact in the raw text anyway (an IP, a credential, a host, a
technology, a vulnerability), call `platform_record_findings` yourself — the
platform's automatic parsers are not exhaustive, and you are the fallback,
not a second hidden model.

State progress in short sentences. A failed/empty/cached result gets one
line, not a re-synthesis of everything else open. Stop and report when the
surface is genuinely exhausted, or ask the operator whether to go deeper.
"""

# Only appended when the operator has set LLM_TOOL_SCHEMA_BUDGET_TOKENS (a
# specific provider's free-tier token-per-minute cap is smaller than the
# full tool catalog — see cli/agent/tools.py's get_tool_schemas()). Every
# other tool still exists and is still callable; this is the one thing that
# changes about how you reach them.
_TOOL_BUDGET_POLICY = """\

Your tool list below is a SUBSET, not the full catalog — this session is on a \
provider with a smaller per-call token budget than the whole tool set needs. \
Nothing is missing permanently: call `platform_tools(query="...")` to search \
the full catalog by name or keyword, then `platform_exec(tool="<name>", \
params_json="{...}")` to run whatever it finds, even though it wasn't in your \
initial list. Use the tools already in front of you first; reach for search \
only when you need something that genuinely isn't there.
"""


async def build_system_prompt(engagement_id: str, *, tool_budget_active: bool = False) -> str:
    ctx = await platform_tools.call_tool(
        "platform_context", {"engagement_id": engagement_id} if engagement_id else {}
    )
    policy = _POLICY + (_TOOL_BUDGET_POLICY if tool_budget_active else "")
    return f"{policy}\n---\n{ctx}"
