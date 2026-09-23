# Plan 08 — Skill system that scales to hundreds of skills

**Baseline:** `10d13ae` · **Risk:** Medium · **Depends on:** nothing (parallelizable) ·
**Size:** ~2 weeks + ongoing content.

## Why

You will keep adding skills, and the current loader will not scale. Today
`knowledge_browser.skills_index_text` builds a **flat `name — description` list capped at 200**
(78 skills now). At Anthropic scale (819 skills) a flat 200-line index is both truncated and
useless as a selector — the LLM can't pick the right skill from 800 one-liners, and a
deterministic planner can't either. This is the "skill loading must be the best" requirement.

The answer is the format + retrieval model the best knowledge set already uses.

## What exists now (verified)
- `knowledge_browser.py`: `list_skills` (indexes top-level + `SKILL.md` routers, excludes
  `reference/*.md`), `get_skill` (pull full text), `skills_index_text(limit=200)`.
- `learned_skills.py`: operator-approved runtime skills (git-ignored) with a similarity advisory
  — good UX to reuse.
- 78 skills across ~19 domain folders. Frontmatter today: `name, description, phase, tags`
  (plus `phases`, `mitre`, `requires_tools` are parsed if present).
- Anthropic set (studied): `SKILL.md` with `name, description (when-to-use hook), domain,
  subdomain, tags, mitre_attack, nist_csf` + structured body (Overview / When to Use /
  Prerequisites / Workflow / verification) + a `references/` subdir for deep dives. 819 skills.

## Steps

### Step 1 — Adopt the Anthropic skill schema (superset of ours)
- Standardize skill frontmatter on: `name, description, domain, phase(s), tags, mitre_attack,
  nist_csf, requires_tools, capabilities`. `description` is the **retrieval hook** — a precise
  "what this does + when to use it" sentence (Anthropic's are exemplary; copy that discipline).
- Keep the two-tier layout we already have: a domain `SKILL.md` router + `reference/*.md`
  deep-dives that are pull-only (never in the index). This is exactly how you stay lean at 800+.

### Step 2 — Two-level retrieval (replaces the flat 200-cap index)
- **Level 1 (routers):** the always-available index is the *domain routers* only (≈20 lines),
  not every skill. Cheap, bounded, never truncated.
- **Level 2 (query):** `find_skills(query|phase|tags|mitre|asset_type)` returns the top-K
  matching skill descriptions, ranked by a description/tag/mitre match against the current
  world-model context (the asset/observation/attack-path in play). The LLM/planner pulls full
  text for the chosen few via `get_skill`.
- This scales: 800 skills never all load; retrieval narrows to the handful relevant to *this*
  asset/technique. Remove the flat `limit=200` index as the primary surface.

### Step 3 — Skills wired to the world model (not phases)
- A skill's applicability is matched against world-model items (asset type, detected tech,
  observation types, active attack path), not a rigid phase number. Retrieval answers "for this
  nginx+GraphQL endpoint with an internal ref, which skills apply?" This is the methodology-as-
  knowledge layer ChatGPT §2 argued for — knowledge that *informs* reasoning, never control flow.

### Step 4 — Specialized-agent skill loading (Strix model)
- When the planner/LLM spawns a specialized subagent (Plan 09 / existing spawn), it loads only
  that agent's relevant skill subset (e.g. an "auth specialist" gets the auth/session/JWT
  skills), via `find_skills`. Mirrors Strix's child-agent specialization and keeps each agent's
  context tight even as the library grows.

### Step 5 — Ingest/adapt external skills (opt-in, curated)
- A converter for Anthropic-format `SKILL.md` → Osprey skill (they're Apache-2.0). **Do not**
  bulk-import 819 (ChatGPT §9: volume ≠ ability; unmatched skills are noise). Curate: import the
  domains you cover, mapped to your `capabilities`/tools. Track provenance (`source: anthropic`).
- Learned skills (`learned_skills.py`) keep their operator-approval gate and now use the same
  schema + retrieval.

### Step 6 — Skill quality gates
- A lint (`scripts/lint_skills.py` exists — extend it): every skill must have a non-empty
  `description` (retrieval depends on it), valid `phase(s)`/`tags`, and (if it names tools)
  `requires_tools` that exist in the registry. CI fails on a malformed skill so the index stays
  trustworthy as it grows.

## Reconnect
- `find_skills` is exposed via MCP (`platform_skills` becomes query-based) and used by the
  context packet (Plan 07) to surface "skills relevant right now."
- The dual-mode planner (Plan 09) uses `find_skills(asset/technique)` to know what techniques
  apply for a no-LLM run.

## Done criteria
- Adding 500 skills does not grow the always-loaded index (routers only); retrieval still
  returns the right top-K in <50ms.
- `find_skills(mitre="T1098.005")` and `find_skills(asset_type="graphql_endpoint")` return the
  correct skills; `get_skill` pulls full text on demand.
- A spawned auth-specialist subagent loads only auth-relevant skills.
- `lint_skills.py` fails a skill with an empty description or a nonexistent `requires_tools`.
