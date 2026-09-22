"""Prompt-customizable flows — Markdown-defined agents and commands.

Lets an operator define entire flows (a system-prompt overlay + tool scoping) or
reusable commands with NO code and NO restart, git-versionable per engagement.
Modeled on OpenCode's agent/command markdown (MIT — patterns, not code). A "mode"
is just an agent whose tool scope denies some tools (e.g. a read-only recon mode
that denies exploit tools). Files, project taking precedence over global:

  <cwd>/.osprey/agents/<name>.md       ·  ~/.osprey/agents/<name>.md
  <cwd>/.osprey/commands/<name>.md     ·  ~/.osprey/commands/<name>.md

Agent frontmatter: `description`, `model` (optional override), `tools`/`allow_tools`
(globs; empty = all), `deny_tools` (globs). Body = a system-prompt overlay appended
to the base policy (so the harness's own guardrails always still apply). Command
frontmatter: `description`; body = a prompt template with $ARGUMENTS / $1..$N.

Tool scoping is OPT-IN and pattern-based (fnmatch on tool names): the DEFAULT agent
has NO restriction (full catalog). A mode only ever NARROWS, and only when the
operator defines one — so this can never silently restrict a real pentest.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Agent:
    name: str
    description: str = ""
    prompt: str = ""            # system-prompt overlay (appended to base policy)
    model: str = ""             # optional per-agent model override
    allow_tools: list[str] = field(default_factory=list)  # globs; empty = all allowed
    deny_tools: list[str] = field(default_factory=list)    # globs; take precedence

    def tool_allowed(self, tool_name: str) -> bool:
        for pat in self.deny_tools:
            if fnmatch.fnmatch(tool_name, pat):
                return False
        if self.allow_tools:
            return any(fnmatch.fnmatch(tool_name, pat) for pat in self.allow_tools)
        return True


@dataclass
class Command:
    name: str
    description: str = ""
    template: str = ""


def _dirs(kind: str) -> list[Path]:
    """Global first, then project — so a later-loaded project file overrides a
    global one of the same name (dict insertion order in the loaders below)."""
    return [Path.home() / ".osprey" / kind, Path.cwd() / ".osprey" / kind]


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split leading `---`-delimited `key: value` frontmatter from the body.
    Deliberately tiny (no YAML dep): keys are lowercased; everything after the
    closing `---` is the body."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm = text[3:end].strip()
    body = text[end + 4:].lstrip("\n")
    meta: dict[str, str] = {}
    for line in fm.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip().lower()] = v.strip()
    return meta, body


def _split_globs(value: str) -> list[str]:
    return [x.strip().strip("\"'") for x in value.strip().strip("[]").split(",") if x.strip()]


def load_agents() -> dict[str, Agent]:
    agents: dict[str, Agent] = {}
    for d in _dirs("agents"):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md")):
            try:
                meta, body = parse_frontmatter(f.read_text(encoding="utf-8"))
            except OSError:
                continue
            name = (meta.get("name") or f.stem).strip().lower()
            if not name:
                continue
            agents[name] = Agent(
                name=name,
                description=meta.get("description", ""),
                prompt=body.strip(),
                model=meta.get("model", ""),
                allow_tools=_split_globs(meta.get("tools") or meta.get("allow_tools") or ""),
                deny_tools=_split_globs(meta.get("deny_tools") or meta.get("deny") or ""),
            )
    return agents


def load_commands() -> dict[str, Command]:
    commands: dict[str, Command] = {}
    for d in _dirs("commands"):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md")):
            try:
                meta, body = parse_frontmatter(f.read_text(encoding="utf-8"))
            except OSError:
                continue
            name = (meta.get("name") or f.stem).strip().lower()
            if not name:
                continue
            commands[name] = Command(name=name, description=meta.get("description", ""), template=body.strip())
    return commands


def expand_command(template: str, args: list[str]) -> str:
    """Substitute $ARGUMENTS (all args joined) and $1..$N (positional)."""
    text = template.replace("$ARGUMENTS", " ".join(args))
    # Replace higher indices first so $10 isn't clobbered by $1.
    for i in range(len(args), 0, -1):
        text = text.replace(f"${i}", args[i - 1])
    return text


def get_agent(name: str) -> Agent | None:
    return load_agents().get((name or "").strip().lower())
