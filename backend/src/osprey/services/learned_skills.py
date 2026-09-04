"""Learned-skills tier — operator-local, gated, cross-engagement methodology.

A deliberately narrow "dynamic skills" capability. The LLM can *propose* a new
skill capturing a **novel, reusable technique** it discovered (a WAF bypass that
worked, an org-specific playbook) — never a merge of existing skills, never
per-target facts (those belong in the engagement graph / operator_memory). A
proposal is inert until the **operator approves** it; only then is it written as a
markdown skill and picked up by the normal description index.

Why this shape (see the design evaluation): merging/auto-evolving the curated
`skills/` library is an anti-pattern — redundancy, drift, quality rot, and it would
be committed + synced (leaking engagement data). So learned skills live in a
git-ignored, user-local `skills/learned/` tree, distinct from the shipped library,
and every one passes a human gate.

Storage (both git-ignored):
  * proposals : skills/learned/.proposals/<id>.json   (never indexed — not .md)
  * active    : skills/learned/<slug>.md               (auto-indexed like any skill)
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from osprey.services.knowledge_browser import list_skills

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_LEARNED_DIR = _PROJECT_ROOT / "skills" / "learned"
_PROPOSALS_DIR = _LEARNED_DIR / ".proposals"

# Phases a learned skill may attach to (matches the shipped phase folders).
_VALID_PHASES = frozenset(
    {"recon", "network", "web", "vuln", "exploit", "osint", "commander", "shared"}
)

_MIN_DESC, _MAX_DESC = 20, 300
_MIN_BODY, _MAX_BODY = 200, 8000
# Reject a proposal whose (name+description+headings) is this similar to an
# existing skill — enforces "novel", not a restatement/merge of what we ship.
_DEDUP_THRESHOLD = 0.72
_TOKEN_RE = re.compile(r"[a-z0-9]+")


class LearnedSkillError(ValueError):
    """A proposal failed validation (bad shape, duplicate, or too similar)."""


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug[:60]


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall((text or "").lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _proposal_path(pid: str) -> Path:
    return _PROPOSALS_DIR / f"{pid}.json"


def _existing_signatures() -> list[tuple[str, set[str]]]:
    """(name, token-set of name+description+title) for every indexed skill."""
    out: list[tuple[str, set[str]]] = []
    for rec in list_skills():
        sig = _tokens(f"{rec['name']} {rec['description']} {rec.get('title', '')}")
        out.append((rec["name"].lower(), sig))
    return out


def _validate(name: str, phase: str, description: str, content: str) -> tuple[str, str]:
    """Return (slug, normalized_phase) or raise LearnedSkillError."""
    name = (name or "").strip()
    slug = _slugify(name)
    if not slug:
        raise LearnedSkillError("name is required (letters/digits).")
    phase = (phase or "").strip().lower()
    if phase not in _VALID_PHASES:
        raise LearnedSkillError(f"phase must be one of: {', '.join(sorted(_VALID_PHASES))}.")
    description = (description or "").strip()
    if not (_MIN_DESC <= len(description) <= _MAX_DESC):
        raise LearnedSkillError(f"description must be {_MIN_DESC}-{_MAX_DESC} chars (got {len(description)}).")
    body = (content or "").strip()
    if not (_MIN_BODY <= len(body) <= _MAX_BODY):
        raise LearnedSkillError(
            f"content must be {_MIN_BODY}-{_MAX_BODY} chars of real methodology (got {len(body)})."
        )
    return slug, phase


def _reject_if_duplicate(
    slug: str, name: str, description: str, title_hint: str, *, exclude_pid: str | None = None
) -> None:
    # Hard name/slug collision against shipped + active learned skills.
    for rec in list_skills():
        if rec["name"].lower() == name.lower() or _slugify(rec["name"]) == slug:
            raise LearnedSkillError(
                f"a skill named '{rec['name']}' already exists — improve it, or pick a distinct technique."
            )
    # Also collide against OTHER pending proposals (never the one being approved).
    for prop in list_proposals():
        if prop.get("id") == exclude_pid:
            continue
        if prop.get("slug") == slug or (prop.get("name", "").lower() == name.lower()):
            raise LearnedSkillError(f"a proposal '{prop.get('name')}' is already pending for this name.")
    # Near-duplicate content guard: this is a *new* technique, not a restatement.
    sig = _tokens(f"{name} {description} {title_hint}")
    for other_name, other_sig in _existing_signatures():
        if _jaccard(sig, other_sig) >= _DEDUP_THRESHOLD:
            raise LearnedSkillError(
                f"too similar to existing skill '{other_name}' — the LLM can already read "
                "that skill; propose only a genuinely new technique."
            )


def propose_skill(
    *,
    name: str,
    phase: str,
    description: str,
    content: str,
    tags: list[str] | None = None,
    engagement_id: str = "",
    evidence: str = "",
) -> dict[str, Any]:
    """Validate + store a proposal. Inert until approved. Raises LearnedSkillError."""
    slug, phase = _validate(name, phase, description, content)
    title_hint = _first_heading(content)
    _reject_if_duplicate(slug, name.strip(), description.strip(), title_hint)

    _PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    pid = uuid.uuid4().hex[:12]
    proposal = {
        "id": pid,
        "name": name.strip(),
        "slug": slug,
        "phase": phase,
        "description": description.strip(),
        "tags": [t.strip() for t in (tags or []) if t.strip()][:8],
        "content": content.strip(),
        "engagement_id": engagement_id,
        "evidence": evidence.strip(),
        "status": "proposed",
        "created_at": time.time(),
    }
    _proposal_path(pid).write_text(json.dumps(proposal, indent=2), encoding="utf-8")
    return proposal


def list_proposals() -> list[dict[str, Any]]:
    if not _PROPOSALS_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(_PROPOSALS_DIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError):
            continue
    return sorted(out, key=lambda d: d.get("created_at", 0), reverse=True)


def get_proposal(pid: str) -> dict[str, Any] | None:
    path = _proposal_path((pid or "").strip())
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return None


def reject_proposal(pid: str) -> bool:
    path = _proposal_path((pid or "").strip())
    if not path.exists():
        return False
    path.unlink()
    return True


def approve_proposal(pid: str) -> dict[str, Any]:
    """Render an approved proposal into an active, indexed learned skill."""
    prop = get_proposal(pid)
    if prop is None:
        raise LearnedSkillError(f"no proposal with id '{pid}'.")
    # Re-check duplicates at approval time (the library may have changed), but never
    # count this proposal itself as the duplicate.
    _reject_if_duplicate(
        prop["slug"], prop["name"], prop["description"],
        _first_heading(prop["content"]), exclude_pid=pid,
    )

    _LEARNED_DIR.mkdir(parents=True, exist_ok=True)
    tags = list(prop.get("tags") or [])
    if "learned" not in tags:
        tags.append("learned")
    frontmatter = (
        "---\n"
        f"name: {prop['slug']}\n"
        f"description: \"{prop['description'].replace(chr(34), chr(39))}\"\n"
        f"phase: {prop['phase']}\n"
        f"tags: [{', '.join(tags)}]\n"
        "source: learned\n"
        "---\n\n"
    )
    body = prop["content"].strip() + "\n"
    if prop.get("evidence"):
        body += f"\n> Grounded in engagement evidence: {prop['evidence']}\n"
    dest = _LEARNED_DIR / f"{prop['slug']}.md"
    dest.write_text(frontmatter + body, encoding="utf-8")
    _proposal_path(pid).unlink(missing_ok=True)
    return {"path": f"learned/{prop['slug']}.md", "name": prop["slug"], "phase": prop["phase"]}


def list_learned() -> list[dict[str, Any]]:
    """Active (approved) learned skills, via the normal index."""
    return [r for r in list_skills() if r["path"].startswith("learned/")]


def _first_heading(text: str) -> str:
    for line in (text or "").splitlines()[:30]:
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip()
    return ""
