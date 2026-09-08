---
name: authoring
description: "How to write a skill for this platform: frontmatter schema, the trigger/negative-trigger rule, when to split a domain into router+reference files, and the requires_tools honesty gate."
phases: [shared]
tags: [meta, authoring]
---

# Authoring a skill

This is the standard `scripts/lint_skills.py` enforces. Read it before adding or editing
anything under `skills/`.

## Frontmatter

```yaml
---
name: kerberoasting
description: >-
  Request and crack service-account TGS tickets for offline password recovery.
  Use when you have any domain foothold/creds and SPNs exist. Do not use for
  AS-REP-roastable users with no pre-auth — use asrep-roasting.
phases: [credential-access, active-directory]
tags: [ad, kerberos, offline-crack]
mitre: [T1558.003]
requires_tools: [impacket-GetUserSPNs, hashcat]
---
```

- `name` — kebab-case, **globally unique across every skill** (`read_skill(name=…)` and
  `platform_skills`' bare-name lookup resolve by this alone — a collision silently returns
  whichever file happens to sort first alphabetically). It does NOT need to match the filename:
  `phase-overview.md` is a shared filename *convention* every phase folder uses (the loader looks
  for that exact filename to eagerly load a spawned agent's phase digest), so its `name:` should
  instead be a folder-specific identifier — e.g. `active-directory/phase-overview.md` carries
  `name: active-directory-overview`, not `name: phase-overview`. `python scripts/lint_skills.py`
  enforces uniqueness.
- `description` — should make clear what the skill does and when it applies; add an explicit
  `Use when …` clause and a `Do not use for … — use <skill-name>` negative trigger **when a
  neighbouring skill could plausibly be confused for this one** — that's the situation a literal
  trigger clause actually earns its keep. Don't force the phrase into an already-clear
  description just to satisfy the linter (it only warns on this, never blocks) — a mechanically
  bolted-on "Use when" is worse than a well-written description without one.
- `phases` — a list, not a scalar, required on every skill. A skill can serve more than one phase
  (Kerberoasting is both `credential-access` and `active-directory`) — list every phase it should
  surface under. There is no legacy single-`phase:` fallback — the parser and every loader require
  the list form.
- `tags` — free-form, for `platform_skills(query=…)` matching.
- `mitre` — ATT&CK technique IDs this skill implements, when applicable. Powers
  `scripts/skill_coverage.py`'s coverage map and `platform_skills(query="T1558")` lookups.
- `requires_tools` — every CLI binary/library this skill actually invokes. The linter cross-checks
  this against `config/kali_allowlist.json` and flags anything missing — this is the honest,
  living "tools we still need to add" list. Don't under-declare to make a skill look
  ready-to-run when it isn't.

**A value may continue onto following lines, as long as each continuation line is indented (or at
least has no `key:` of its own).** The frontmatter parser (`knowledge_browser.parse_frontmatter`)
is deliberately minimal — no PyYAML — but does join a wrapped value across lines, e.g.:
```yaml
description: A long description that reads better wrapped across two or three
  lines than crammed onto one, as long as continuation lines are indented.
requires_tools: [impacket-GetUserSPNs, impacket-secretsdump, netexec, certipy-ad,
  bloodhound-ce-python]
```
A continuation line that is NOT indented (starts at column 0) is read as a new key, not a
continuation — always indent. `python scripts/lint_skills.py` flags a list field that opens with
`[` and never closes.

## Structure — one file, unless the domain genuinely doesn't fit

Default: one flat file, `<phase>/<name>.md`. Write it dense — attack surface, concrete commands
(not just "use tool X"), a decision tree for which technique applies when, a **Do not** section,
and false-positive guidance where relevant. Look at `web/oauth-and-jwt.md` or
`exploit/cve-exploitation.md` for the bar.

Split into a router + references only when a domain is broad enough that one file would blow
past ~250 lines *and* the extra material is genuinely separable (e.g. per-CVE exploit chains,
per-DBMS payload variants):
```
skills/<phase>/<name>/
  SKILL.md          # router: when-to-use, decision tree, which tool — ≤150 lines
  reference/
    <topic>.md       # deep technique, pulled on demand by path — ≤200 lines
```
`platform_skills(path="<phase>/<name>/reference/<topic>.md")` resolves any file under `skills/`
directly — reference files are never eagerly loaded, only pulled when the router names them.

## Do not

- Invent a technique or tool flag you haven't verified — no fabricated CVEs, no guessed CLI
  syntax. If unsure, say so in the skill rather than asserting it.
- Duplicate an existing skill's content — cross-list via `phases:`/`tags:` instead of copy-pasting.
- Write a `Do not` section that just restates governance (scope/authorization) — that's
  `shared/governance-rules.md`'s job; link to it instead of repeating it.
- Copy content from a third-party skill library verbatim without recording it in
  `THIRD_PARTY_NOTICES.md` and adding the per-file attribution comment described there.
