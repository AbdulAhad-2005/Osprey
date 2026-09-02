"""Load markdown skills for agent prompts.

Full-text loads strip the YAML frontmatter (metadata is for the registry, not the
prompt). The description-indexed helpers here are how the active phase's skills are
surfaced to an agent without dumping whole directories — matching the pull-based
MCP path.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from osprey.core.config import get_settings
from osprey.services.knowledge_browser import (
    parse_frontmatter,
    skills_index_text,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_SKILLS_DIR = _PROJECT_ROOT / "skills"


def _body(text: str) -> str:
    """Strip leading YAML frontmatter — prompts get methodology, not metadata."""
    _, body = parse_frontmatter(text)
    return body.strip()


def _read_skill(relative_path: str) -> str:
    path = _SKILLS_DIR / relative_path
    if not path.exists():
        return ""
    return _body(path.read_text(encoding="utf-8"))


def load_skill(relative_path: str) -> str:
    return _read_skill(relative_path)


def _shared_skill_bits() -> list[str]:
    parts: list[str] = []
    for shared_name in (
        "finding-confidence.md",
        "escalation-playbook.md",
        "sister-domain-discovery.md",
    ):
        shared = _SKILLS_DIR / "shared" / shared_name
        if shared.exists():
            parts.append(_body(shared.read_text(encoding="utf-8")))
    # Always-on adaptive judgment (target-agnostic)
    adaptive = _SKILLS_DIR / "commander" / "adaptive-coverage.md"
    if adaptive.exists():
        parts.append(_body(adaptive.read_text(encoding="utf-8")))
    return parts


def load_skills_for_phase(
    phase: str,
    *,
    slim: bool | None = None,
    allow_missing: bool = False,
) -> str:
    """Load skills for a focus name. Missing dirs return '' when allow_missing."""
    if slim is None:
        slim = bool(get_settings().slim_context_skills)

    phase_dir = _SKILLS_DIR / phase
    parts: list[str] = []

    if not phase_dir.exists():
        if allow_missing:
            return ""
        # No invented stage stubs — shared methodology only
        parts.extend(_shared_skill_bits())
        return "\n\n---\n\n".join(p for p in parts if p)

    overview = phase_dir / "phase-overview.md"
    if overview.exists():
        parts.append(_body(overview.read_text(encoding="utf-8")))

    if not slim:
        for path in sorted(phase_dir.glob("*.md")):
            if path.name in ("phase-overview.md", "agent-system.md"):
                continue
            content = _body(path.read_text(encoding="utf-8"))
            if content:
                parts.append(f"## {path.stem}\n\n{content}")

    parts.extend(_shared_skill_bits())
    return "\n\n---\n\n".join(p for p in parts if p)


def phase_skill_index(phase: str, *, limit: int = 80) -> str:
    """`name — description` index for a phase (plus shared methodology).

    The description-indexed surface an agent reads to decide *which* skill to pull.
    """
    return skills_index_text(phase=(phase or "").strip().lower(), limit=limit)


def active_phase_skill_digest(phase: str) -> str:
    """What Executor B injects for the active phase, in place of the old whole-dir dump.

    The phase-overview methodology in full (the anchor), then a `name — description`
    index of every other skill for this phase. Full text of any one is pulled on
    demand via the ``read_skill`` control tool — same pull model as the MCP path,
    so neither executor truncates a skill dir or blows up small models' context.
    """
    focus = (phase or "").strip().lower()
    parts: list[str] = []
    overview = _SKILLS_DIR / focus / "phase-overview.md"
    if overview.exists():
        parts.append(_body(overview.read_text(encoding="utf-8")))
    index = phase_skill_index(focus)
    if index and not index.startswith("(no skills"):
        parts.append(
            "MORE SKILLS FOR THIS PHASE (pull full text with read_skill(name=…) only when relevant):\n"
            + index
        )
    return "\n\n---\n\n".join(p for p in parts if p)


def _load_dir(role: str) -> str:
    role_dir = _SKILLS_DIR / role
    if not role_dir.exists():
        return ""
    parts: list[str] = []
    for path in sorted(role_dir.glob("*.md")):
        content = _body(path.read_text(encoding="utf-8"))
        if content:
            parts.append(content)
    return "\n\n---\n\n".join(parts)


def load_skills_for_agent(role: str, phase: str | None = None) -> str:
    """Load skills for commander, summary, or optional focus agents."""
    if role == "commander":
        return _load_dir("commander")
    if role == "summary":
        return _load_dir("summary")
    # Any skills/<role> directory — adaptable, not a fixed stage list
    phase_skills = load_skills_for_phase(role, allow_missing=True)
    agent_system = _read_skill(f"{role}/agent-system.md")
    if agent_system or phase_skills:
        if agent_system and phase_skills:
            return f"{agent_system}\n\n---\n\n{phase_skills}"
        return agent_system or phase_skills
    if phase:
        return load_skills_for_phase(phase, allow_missing=True)
    return ""


def load_skill_for_task(task_id: str) -> str:
    from osprey.services.task_registry import get_task

    task = get_task(task_id)
    if task is None or not task.skill_file:
        return ""
    return _read_skill(task.skill_file)


@lru_cache(maxsize=1)
def load_shared_context() -> str:
    parts = []
    for name in ("finding-confidence.md", "governance-rules.md", "tool-selection-ux.md"):
        content = _read_skill(f"shared/{name}")
        if content:
            parts.append(content)
    return "\n\n---\n\n".join(parts)
