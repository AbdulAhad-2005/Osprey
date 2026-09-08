"""Skill/config discovery — the single description-indexed skill registry.

Every skill under ``skills/<phase>/*.md`` carries YAML frontmatter
(``name``, ``description``, ``phase``, ``tags``). This module is the one place
that parses it, so both executors (the MCP tool-surface and the backend
self-harness) read skills the same way: an index of ``name — description`` lines
the LLM can triage, with full text pulled on demand.
"""

from __future__ import annotations

from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_SKILLS_DIR = _PROJECT_ROOT / "skills"
_CONFIG_DIR = _PROJECT_ROOT / "config"

_CONFIG_ALLOWLIST = frozenset(
    {
        "playbooks",
        "playbooks.yaml",
        "playbooks.json",
        "escalation_matrix",
        "escalation_matrix.yaml",
        "recon_network_tools",
        "recon_network_tools.yaml",
        "vuln_tools",
        "vuln_tools.yaml",
        "osint_tools",
        "osint_tools.yaml",
        "tech_dispatch",
        "tech_dispatch.yaml",
        "ingest_rules",
        "ingest_rules.yaml",
        "ingest_rules.json",
        "correlation_rules",
        "correlation_rules.yaml",
        "parallelism",
        "parallelism.yaml",
        "phase_pipeline",
        "phase_pipeline.yaml",
        "thinking_model",
        "thinking_model.yaml",
        "thinking_model.json",
    }
)


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split a leading ``---`` YAML block off a skill file.

    Returns (metadata, body). Metadata parsing is intentionally minimal (no PyYAML
    dependency for such a flat schema): ``key: value`` scalars and ``tags: [a, b]``
    lists. A value may continue onto following lines — any line that is indented
    or has no ``key:`` of its own is appended (space-joined) to the previous
    key's value, so a long ``description:`` or a wrapped ``tags: [a, b,\\n  c]``
    reads naturally instead of forcing everything onto one line. Files without
    frontmatter return ({}, original text).
    """
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
    """Parse a `key: [a, b]` or `key: a, b` frontmatter scalar into a list."""
    return [v.strip() for v in (meta.get(key) or "").strip("[]").split(",") if v.strip()]


def _skill_record(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    meta, body = parse_frontmatter(text)
    rel = path.relative_to(_SKILLS_DIR).as_posix()
    folder = rel.split("/", 1)[0] if "/" in rel else ""
    name = meta.get("name") or path.stem
    description = meta.get("description") or _first_heading(body) or path.stem.replace("-", " ")
    tags = _parse_list_field(meta, "tags")
    # `phases:` (list) is the only schema — a skill can serve more than one
    # phase (e.g. a Kerberoasting skill is both credential-access and
    # active-directory); scripts/lint_skills.py errors on a file missing it.
    # Folder name is a runtime-only safety net (never treat as valid input) so
    # one malformed file can't take the whole skills index down with it.
    phases = _parse_list_field(meta, "phases") or [folder]
    mitre = _parse_list_field(meta, "mitre")
    requires_tools = _parse_list_field(meta, "requires_tools")
    return {
        "path": rel,
        "name": name,
        "phase": phases[0],
        "phases": phases,
        "description": description,
        "title": _first_heading(body) or path.stem.replace("-", " "),
        "tags": tags,
        "mitre": mitre,
        "requires_tools": requires_tools,
        "chars": len(text),
    }


def list_skills(*, phase: str = "", query: str = "") -> list[dict]:
    """Index all skills with name + description + phases + tags.

    Only top-level skill files and `<domain>/SKILL.md` router files are
    indexed — a domain's `reference/*.md` deep-dives are deliberately excluded
    so they stay pull-only-when-relevant (never bloat the index).
    """
    if not _SKILLS_DIR.exists():
        return []
    phase = (phase or "").strip().lower()
    query = (query or "").strip().lower()
    out: list[dict] = []
    for path in sorted(_SKILLS_DIR.rglob("*.md")):
        rel_parts = path.relative_to(_SKILLS_DIR).parts
        if "reference" in rel_parts[:-1]:
            continue
        if len(rel_parts) > 2 and path.name != "SKILL.md":
            continue
        rec = _skill_record(path)
        if phase and phase not in rec["phases"] and not rec["path"].startswith(phase + "/"):
            continue
        if query:
            hay = " ".join(
                [
                    rec["path"],
                    rec["name"],
                    rec["description"],
                    rec["title"],
                    " ".join(rec["tags"]),
                    " ".join(rec["mitre"]),
                ]
            ).lower()
            if query not in hay:
                continue
        out.append(rec)
    return out


def get_skill(path: str) -> dict | None:
    """Resolve a skill by relative path OR by bare ``name`` and return full text."""
    rel = (path or "").strip().lstrip("/").replace("\\", "/")
    if rel.startswith("skills/"):
        rel = rel[len("skills/") :]
    if ".." in rel or rel.startswith("/"):
        return None
    full = (_SKILLS_DIR / rel).resolve()
    try:
        full.relative_to(_SKILLS_DIR.resolve())
        exists = full.exists() and full.is_file()
    except ValueError:
        exists = False
    if not exists:
        # Fall back to a name lookup (e.g. read_skill(name="nuclei-scanning")).
        bare = rel.rsplit("/", 1)[-1].removesuffix(".md").lower()
        match = next(
            (r for r in list_skills() if r["name"].lower() == bare or r["path"].lower() == rel.lower()),
            None,
        )
        if match is None:
            return None
        full = _SKILLS_DIR / match["path"]
    text = full.read_text(encoding="utf-8", errors="replace")
    meta, body = parse_frontmatter(text)
    return {
        "path": full.relative_to(_SKILLS_DIR).as_posix(),
        "name": meta.get("name") or full.stem,
        "description": meta.get("description") or "",
        "title": _first_heading(body) or full.stem,
        "content": text,
    }


def list_configs() -> list[dict]:
    if not _CONFIG_DIR.exists():
        return []
    out = []
    for path in sorted(_CONFIG_DIR.iterdir()):
        if not path.is_file():
            continue
        if path.name not in _CONFIG_ALLOWLIST and path.stem not in _CONFIG_ALLOWLIST:
            continue
        out.append({"name": path.stem, "file": path.name, "chars": path.stat().st_size})
    return out


def get_config(name: str) -> dict | None:
    raw = (name or "").strip().lower()
    if not raw:
        return None
    # Prefer YAML (source of truth); JSON is an optional mirror.
    candidates = []
    stem = raw.replace(".yaml", "").replace(".yml", "").replace(".json", "")
    if stem not in {x.replace(".yaml", "").replace(".json", "") for x in _CONFIG_ALLOWLIST}:
        if raw not in _CONFIG_ALLOWLIST:
            return None
    for ext in (".yaml", ".yml", ".json"):
        p = _CONFIG_DIR / f"{stem}{ext}"
        if p.exists():
            candidates.append(p)
    if not candidates and raw in _CONFIG_ALLOWLIST:
        p = _CONFIG_DIR / raw
        if p.exists():
            candidates.append(p)
    if not candidates:
        return None
    path = candidates[0]
    return {
        "name": stem,
        "file": path.name,
        "content": path.read_text(encoding="utf-8", errors="replace"),
    }


def skills_index_text(*, phase: str = "", limit: int = 200) -> str:
    """`name — description` index. Pass phase= to surface only that phase's skills
    (plus always-relevant shared/commander methodology), so the conductor can
    anchor skills to the active phase instead of dumping the whole catalog."""
    if phase:
        items = list_skills(phase=phase) + list_skills(phase="shared")
    else:
        items = list_skills()
    items = items[:limit]
    if not items:
        return "(no skills found under skills/)"
    header = (
        f"Skills for the {phase} phase (call platform_skills / read_skill with the name for full text):"
        if phase
        else "Call platform_skills(path='…') for full text. Index:"
    )
    lines = [header]
    for it in items:
        lines.append(f"- {it['name']} — {it['description']}")
    return "\n".join(lines)


def _first_heading(text: str) -> str:
    for line in text.splitlines()[:30]:
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip()
    return ""
