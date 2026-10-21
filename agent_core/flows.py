"""Prompt-defined flows: operator-authored agent modes and custom slash commands.

No code change is needed to add a mode or a command — drop a markdown file in
`.osprey/agents/` or `.osprey/commands/` (resolved relative to the CLI's current
working directory, same convention as `.env`/`load_dotenv()`). `handle_agent` /
`execute_command` in `cli/commands/slash.py` are the only callers.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Minimal `--- key: value ---` frontmatter parse — mirrors
    ``osprey.services.knowledge_browser.parse_frontmatter`` byte-for-byte, but
    duplicated rather than imported: ``cli/`` is an independently installable
    package (its own pyproject/requirements) with no dependency on the backend."""
    stripped = text.lstrip("﻿")
    if not stripped.startswith("---"):
        return {}, text
    lines = stripped.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    meta: dict[str, str] = {}
    body_start = None
    last_key: str | None = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            body_start = i + 1
            break
        raw = lines[i]
        if not raw.strip():
            continue
        if last_key is not None and (":" not in raw or raw[:1].isspace()):
            meta[last_key] = (meta[last_key] + " " + raw.strip()).strip()
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        meta[key] = value.strip().strip('"').strip("'")
        last_key = key
    if body_start is None:
        return {}, text
    body = "\n".join(lines[body_start:]).lstrip("\n")
    return meta, body


def _parse_list_field(meta: dict[str, str], key: str) -> list[str]:
    return [v.strip() for v in (meta.get(key) or "").strip("[]").split(",") if v.strip()]


def _osprey_dir(*parts: str) -> Path:
    return Path.cwd().joinpath(".osprey", *parts)


@dataclass
class Agent:
    """A prompt-defined mode: a system-prompt overlay plus an optional tool scope
    and model override, authored as ``.osprey/agents/<name>.md``."""

    name: str
    description: str = ""
    prompt: str = ""
    allow_tools: list[str] = field(default_factory=list)
    deny_tools: list[str] = field(default_factory=list)
    model: str = ""

    def tool_allowed(self, tool_name: str) -> bool:
        """Glob-matched allow/deny, deny wins. Empty allow-list = everything
        allowed (deny still applies). Bound, so ``agent.tool_allowed`` is directly
        usable as ``Runner``'s ``Callable[[str], bool]`` tool_filter."""
        if any(fnmatch.fnmatch(tool_name, pat) for pat in self.deny_tools):
            return False
        if self.allow_tools:
            return any(fnmatch.fnmatch(tool_name, pat) for pat in self.allow_tools)
        return True


def load_agents() -> dict[str, Agent]:
    """Every `.osprey/agents/*.md`, keyed by lowercase name. An empty or missing
    directory just yields no agents — this is opt-in, never required."""
    out: dict[str, Agent] = {}
    agents_dir = _osprey_dir("agents")
    if not agents_dir.is_dir():
        return out
    for path in sorted(agents_dir.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        meta, body = _parse_frontmatter(text)
        name = (meta.get("name") or path.stem).strip().lower()
        if not name:
            continue
        out[name] = Agent(
            name=name,
            description=meta.get("description", ""),
            prompt=body.strip(),
            allow_tools=_parse_list_field(meta, "tools"),
            deny_tools=_parse_list_field(meta, "deny_tools"),
            model=meta.get("model", ""),
        )
    return out


@dataclass
class Command:
    """A prompt-defined slash command: ``.osprey/commands/<name>.md``'s body is a
    template expanded with the invocation's args, then driven as a normal prompt."""

    name: str
    description: str = ""
    template: str = ""


def load_commands() -> dict[str, Command]:
    out: dict[str, Command] = {}
    commands_dir = _osprey_dir("commands")
    if not commands_dir.is_dir():
        return out
    for path in sorted(commands_dir.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        meta, body = _parse_frontmatter(text)
        name = (meta.get("name") or path.stem).strip().lower()
        if not name:
            continue
        out[name] = Command(name=name, description=meta.get("description", ""), template=body.strip())
    return out


def expand_command(template: str, args: list[str]) -> str:
    """Expand ``$ARGUMENTS`` (all args, space-joined) and ``$1``..``$N``
    (positional) in a command template. An unmatched ``$N`` is left as-is rather
    than blanked, so a malformed invocation is visibly wrong, not silently short."""
    out = template.replace("$ARGUMENTS", " ".join(args))
    # Replace higher indices first so a $1 pass never clobbers the leading digit
    # of $10..$N. Unmatched $N (index > len(args)) is left as-is by construction.
    for i in range(len(args), 0, -1):
        out = out.replace(f"${i}", args[i - 1])
    return out
