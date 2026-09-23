# Plan 04 — Learning false-positive cache (a noise pattern dies once, forever)

**Baseline:** `10d13ae` · **Risk:** Low · **Depends on:** 03 · **Size:** ~3–4 days.

## Why

Plans 02–03 stop *manufacturing* false positives. This plan stops a real-but-unwanted finding
pattern from **recurring** across engagements. It is Pentest-Swarm's single most practical
anti-noise mechanism, and nothing in Osprey has it.

Pentest-Swarm (`internal/pipeline/fpcache/fpcache.go`): a persistent, append-only
`fp-cache.jsonl` of `(target, attack_category, title_contains, reason)` patterns. The H1/Bugcrowd
report template has a one-click "mark as false positive" link that appends a pattern; every
future scan's classifier suppresses matches automatically. Human judgment, captured once,
applied forever.

## What exists now (verified)
- No FP suppression that learns. The prior "advisory similarity" work on learned-skills is the
  closest existing pattern (operator marks → persisted) and is a good template for the UX.
- Report/findings surfaces (CLI `/findings`, `platform_findings`, report outline) already list
  findings with ids.

## Steps

### Step 1 — FP-cache store
- `fp_cache` persistence (git-ignored, user/operator-local, like learned skills):
  patterns of `(target_glob, finding_type, title_contains, observation_signature, reason,
  marked_by, marked_at)`.
- `matches(candidate) -> Pattern|None` — case-insensitive/substring/glob match, O(n) over the
  in-memory patterns (loaded once per engagement).
- Cross-engagement by default (a noise pattern on nginx is noise everywhere), with an optional
  `target_glob` to scope a mark to one target when appropriate.

### Step 2 — Wire into the promotion pipeline (Plan 03)
- In `promote_observations` and `platform_file_finding`, consult `fp_cache.matches(candidate)`
  **before** running validation. A match suppresses promotion (records it as a suppressed
  candidate with the FP reason, so it's auditable, not silently dropped).
- Suppression is at the *candidate* stage — we never spend a validation/PoC action on a
  known-noise pattern.

### Step 3 — One-click marking
- CLI: `/finding fp <id> [reason]` — appends the finding's signature to the FP-cache and
  retracts it from the current engagement.
- MCP: `platform_mark_false_positive(finding_id, reason)` — same, for an external harness/operator.
- Report templates (Plan 03 output) include the finding signature so a reviewer can mark it later.

### Step 4 — Surfacing + safety
- `/fp list` and `platform_fp_list` show current patterns with reasons (so the operator can
  audit/prune — a bad FP mark shouldn't hide real findings forever).
- A pattern is advisory metadata, never a hard delete of evidence: the underlying Observations
  and Evidence remain; only *promotion to Finding* is suppressed. If a mark was wrong, removing
  the pattern re-enables promotion.

## Reconnect
- Reuses the learned-skills operator-approval UX pattern (`cli/commands/slash.py`) — consistent
  operator surface.
- Feeds the benchmark: a fixture can include a pre-seeded FP pattern to prove suppression.

## Done criteria
- Marking a finding as FP appends a pattern; re-running the same engagement (replay) no longer
  promotes that pattern to a finding.
- Suppressed candidates are visible in an audit view (not silently gone).
- `/fp list` shows patterns; removing one re-enables promotion on replay.
- Benchmark: a fixture with a seeded FP pattern shows that finding suppressed with the recurrence
  count for that pattern at 0 across a second replay.
