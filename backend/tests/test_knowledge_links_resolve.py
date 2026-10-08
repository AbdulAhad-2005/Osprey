"""D2 — every DECLARED cross-reference between the rule layer (config/*.yaml)
and the skill layer (skills/*.md) must resolve. A dispatch/catalog rule that
names a skill_file which doesn't exist is drift (the A2 class of bug) and fails
here loudly — without forcing every rule to declare a skill (guidance-only
skills and rule-less skills stay first-class; the check only fires on a
declared reference that dangles)."""

from __future__ import annotations

from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _REPO_ROOT / "config"
_SKILLS_DIR = _REPO_ROOT / "skills"


def _collect_skill_files(node) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "skill_file" and isinstance(value, str) and value.strip():
                found.append(value.strip())
            else:
                found.extend(_collect_skill_files(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_collect_skill_files(item))
    return found


def test_every_declared_skill_file_reference_resolves():
    missing: list[str] = []
    for cfg in sorted(_CONFIG_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # a malformed config is its own failure
            raise AssertionError(f"{cfg.name} is not valid YAML: {exc}") from exc
        for ref in _collect_skill_files(data):
            if not (_SKILLS_DIR / ref).is_file():
                missing.append(f"{cfg.name} -> skills/{ref}")
    assert not missing, "dangling skill_file references:\n" + "\n".join(missing)
