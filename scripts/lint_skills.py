#!/usr/bin/env python3
"""Validate skills/ against skills/AUTHORING.md. Exit 1 on any ERROR.

Also prints a WARN report of `requires_tools` entries not yet present in
config/kali_allowlist.json — the living "tools still to add" list referenced
from AUTHORING.md; that report is informational, not a lint failure, since
skills are written ahead of tooling by design.

Usage: python scripts/lint_skills.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "backend" / "src"))

from osprey.services.knowledge_browser import parse_frontmatter  # noqa: E402

_SKILLS_DIR = _ROOT / "skills"
_ALLOWLIST_PATH = _ROOT / "config" / "kali_allowlist.json"
_ROUTER_LINE_CAP = 150
_REFERENCE_LINE_CAP = 200
_FLAT_SKILL_LINE_CAP = 250
_TRIGGER_RE = re.compile(r"use when", re.IGNORECASE)


def _known_binaries() -> set[str]:
    if not _ALLOWLIST_PATH.exists():
        return set()
    data = json.loads(_ALLOWLIST_PATH.read_text(encoding="utf-8"))
    return {b.lower() for b in data.get("binaries", [])}


def _is_reference(path: Path) -> bool:
    return "reference" in path.relative_to(_SKILLS_DIR).parts[:-1]


def _is_router(path: Path) -> bool:
    return path.name == "SKILL.md"


_LIST_FIELDS = ("tags", "phases", "mitre", "requires_tools")


def _malformed_list_fields(meta: dict[str, str]) -> list[str]:
    """A list field's value, after parse_frontmatter's continuation-joining,
    should be a clean `[a, b, c]` — flag anything that opens with `[` but
    never closes (a genuine typo, not a wrapping issue: continuation across
    lines is joined correctly before this check runs)."""
    bad = []
    for key in _LIST_FIELDS:
        value = meta.get(key, "")
        if value.startswith("[") and not value.endswith("]"):
            bad.append(key)
    return bad


def _line_cap_for(path: Path) -> int | None:
    if _is_reference(path):
        return _REFERENCE_LINE_CAP
    if _is_router(path):
        return _ROUTER_LINE_CAP
    if path.name == "AUTHORING.md":
        return None
    return _FLAT_SKILL_LINE_CAP


def lint() -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warns: list[str] = []
    known_tools = _known_binaries()
    missing_tools: dict[str, set[str]] = {}
    # `name:` is a globally unique identifier — the thing read_skill(name=…) and
    # platform_skills' bare-name lookup resolve by. It is NOT required to match
    # the filename: phase-overview.md is a shared filename *convention* every
    # phase folder uses (the loader looks for it by that exact name), but each
    # one's `name:` must still be unique, or a bare-name lookup silently
    # resolves to whichever collision sorts first alphabetically.
    seen_names: dict[str, str] = {}

    md_files = sorted(_SKILLS_DIR.rglob("*.md"))
    for path in md_files:
        rel = path.relative_to(_SKILLS_DIR).as_posix()
        if path.name == "AUTHORING.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = parse_frontmatter(text)

        if not meta:
            errors.append(f"{rel}: no frontmatter block")
            continue

        for bad_key in _malformed_list_fields(meta):
            errors.append(f"{rel}: `{bad_key}` opens with `[` but never closes it")

        name = meta.get("name", "")
        if not name:
            errors.append(f"{rel}: missing `name` in frontmatter")
        elif name in seen_names:
            errors.append(f"{rel}: name '{name}' collides with {seen_names[name]} — names must be globally unique (read_skill/bare platform_skills lookup resolve by name alone)")
        else:
            seen_names[name] = rel

        description = meta.get("description", "")
        if not description:
            errors.append(f"{rel}: missing `description`")
        elif not _TRIGGER_RE.search(description):
            # A recommendation, not a mandate: a literal 'Use when' phrase helps
            # disambiguate when several skills could plausibly apply, but a lot
            # of good descriptions convey the same thing without that exact
            # wording — forcing the phrase in everywhere would mean mechanically
            # mangling already-clear prose just to satisfy the linter, which is
            # worse than the problem it solves. Flag it, don't block on it.
            warns.append(f"{rel}: description has no 'Use when' trigger clause (consider adding one if this skill could be confused with a neighbour)")

        if not _is_reference(path):
            if not meta.get("phases"):
                errors.append(f"{rel}: missing `phases` (list) — the legacy single `phase:` scalar is no longer supported")

        cap = _line_cap_for(path)
        line_count = len(text.splitlines())
        if cap is not None and line_count > cap:
            errors.append(f"{rel}: {line_count} lines exceeds the {cap}-line cap")

        requires_tools = [
            t.strip() for t in (meta.get("requires_tools") or "").strip("[]").split(",") if t.strip()
        ]
        for tool in requires_tools:
            if tool.lower() not in known_tools:
                missing_tools.setdefault(tool, set()).add(rel)

        if _is_router(path):
            ref_dir = path.parent / "reference"
            if ref_dir.exists():
                referenced = {
                    f.name for f in ref_dir.glob("*.md") if f.name in body
                }
                all_refs = {f.name for f in ref_dir.glob("*.md")}
                for orphan in sorted(all_refs - referenced):
                    errors.append(
                        f"{path.parent.name}/reference/{orphan}: not linked from {rel}"
                    )

    if missing_tools:
        warns.append("Tools referenced by skills but not yet in config/kali_allowlist.json:")
        for tool, users in sorted(missing_tools.items()):
            warns.append(f"  - {tool} (needed by: {', '.join(sorted(users))})")

    return errors, warns


def main() -> int:
    errors, warns = lint()
    for w in warns:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        print(f"\n{len(errors)} error(s).")
        return 1
    print(f"OK — {len(list(_SKILLS_DIR.rglob('*.md')))} skill files linted clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
