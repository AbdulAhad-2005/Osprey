#!/usr/bin/env python3
"""Convert an Anthropic-format SKILL.md into Osprey's skill schema —
plans/harness/08-skill-system-at-scale.md Step 5.

Anthropic's skills (Apache-2.0) use: name, description, domain, subdomain,
tags, mitre_attack, nist_csf. Osprey's schema (services/knowledge_browser.py)
is a superset: name, description, phases, tags, mitre, domain, nist_csf,
requires_tools, capabilities.

Deliberately ONE FILE AT A TIME with a REQUIRED --phase, not a bulk importer:
the plan is explicit that volume != ability (ChatGPT §9) and unmatched skills
are noise — mapping an Anthropic "domain" to an Osprey phase needs a human
judgment call this script won't guess at. Curate what you actually cover.

Usage:
    python scripts/convert_anthropic_skill.py <source.md> --phase web [--tags extra,tags] [--force]
    # writes skills/<phase>/<name>.md (or pass --out for a specific path)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "backend" / "src"))

from osprey.services.knowledge_browser import parse_frontmatter  # noqa: E402

_SKILLS_DIR = _ROOT / "skills"


def _fmt_list(items: list[str]) -> str:
    return "[" + ", ".join(items) + "]"


def convert(source_text: str, *, phase: str, extra_tags: list[str] | None = None) -> tuple[str, str]:
    """Returns (osprey_frontmatter_text, name) — the caller writes the file."""
    meta, body = parse_frontmatter(source_text)
    if not meta:
        raise ValueError("source file has no frontmatter block — not a valid SKILL.md")
    name = meta.get("name", "").strip()
    if not name:
        raise ValueError("source frontmatter has no `name`")
    description = meta.get("description", "").strip()
    if not description:
        raise ValueError("source frontmatter has no `description` — required, it's the retrieval hook")

    tags = [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()]
    subdomain = meta.get("subdomain", "").strip()
    if subdomain and subdomain not in tags:
        tags.append(subdomain)
    for t in extra_tags or []:
        if t not in tags:
            tags.append(t)

    mitre = [m.strip() for m in meta.get("mitre_attack", "").strip("[]").split(",") if m.strip()]
    nist_csf = [n.strip() for n in meta.get("nist_csf", "").strip("[]").split(",") if n.strip()]
    domain = meta.get("domain", "").strip()

    lines = [
        "---",
        f"name: {name}",
        f'description: "{description}"',
        f"phases: [{phase}]",
    ]
    if tags:
        lines.append(f"tags: {_fmt_list(tags)}")
    if mitre:
        lines.append(f"mitre: {_fmt_list(mitre)}")
    if nist_csf:
        lines.append(f"nist_csf: {_fmt_list(nist_csf)}")
    if domain:
        lines.append(f"domain: {domain}")
    # Provenance — this is imported content, not authored in-repo; keeps the
    # library honest about where a skill's judgment calls came from.
    lines.append("source: anthropic")
    lines.append("---")
    lines.append("")
    lines.append(body.rstrip())
    lines.append("")
    return "\n".join(lines), name


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", type=Path, help="Anthropic-format SKILL.md to convert")
    ap.add_argument("--phase", required=True, help="Osprey phase folder this skill belongs under (required — curation, not auto-mapping)")
    ap.add_argument("--tags", default="", help="Comma-separated extra tags to add")
    ap.add_argument("--out", type=Path, default=None, help="Output path (default: skills/<phase>/<name>.md)")
    ap.add_argument("--force", action="store_true", help="Overwrite an existing file")
    args = ap.parse_args()

    if not args.source.is_file():
        print(f"ERROR: {args.source} not found", file=sys.stderr)
        return 1

    extra_tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    try:
        converted, name = convert(args.source.read_text(encoding="utf-8"), phase=args.phase, extra_tags=extra_tags)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    out_path = args.out or (_SKILLS_DIR / args.phase / f"{name}.md")
    if out_path.exists() and not args.force:
        print(f"ERROR: {out_path} already exists — pass --force to overwrite", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(converted, encoding="utf-8")
    try:
        shown_path = out_path.resolve().relative_to(_ROOT)
    except ValueError:
        shown_path = out_path.resolve()
    print(f"Wrote {shown_path} — run scripts/lint_skills.py before committing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
