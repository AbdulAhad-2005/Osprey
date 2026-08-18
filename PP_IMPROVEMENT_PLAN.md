# Pentest Platform — Improvement Plan

**Purpose:** consolidate the full architecture review into one plan. End goal: the driving
LLM spends its turn/context budget on judgment calls (what's exploitable, what's worth
chasing, when to stop) — not on mechanical busywork the platform should be doing for it.
Every item below either removes something producing wrong/noisy signal, automates
something mechanical so the LLM doesn't have to, or makes the LLM's read path leaner
and more trustworthy. Follow the existing convention: no narrow patches bound to a
reported edge case — root-cause fix, old implementation removed, not left in place
alongside a special case.

---

## The thesis

HexStrike-AI (another pentesting tool , repo cloned) wins on raw tool breadth (150+ tools, all wired) and on **mechanical
adaptiveness** — `ParameterOptimizer` auto-tunes nmap/gobuster/sqlmap flags per target,
`GracefulDegradation` auto-retries with a fallback tool on failure — all in deterministic
Python, costing the connecting LLM zero turns. These features of hexstrike are good and fruitful to encorporate in our tool, but need to see our parameter handling and fallback logic as well.
Dont blindly start implementing, see whats best of both the worlds or some better approach without any unecessary complexity.

Need to look deeply into memory improvements including removing bad implementation.
Some improvements are discussed below (need to verify)
PP's structural advantage is real: a durable Postgres findings store, an engagement
graph, evidence-grade claims, a 3-tier parser pipeline (typed parser → LLM structuring
fallback → regex safety net → raw output never dropped) that's already better than
anything HexStrike does with output. But two things currently cancel that advantage out:

1. **PP pushes mechanical/tactical work onto the LLM that HexStrike automates in
   Python** (parameter tuning, retry/fallback selection) — costing turns HexStrike
   doesn't spend.
2. **PP's memory layer currently pollutes itself** — a background correlator
   auto-writes unconfirmed "hypothesis" edges into the same store real evidence lives
   in, and a coverage/gap engine pushes uninvited advisory noise into every turn's
   context.

Fix both and PP wins on the one axis HexStrike structurally cannot compete on:
durable, evidence-chained findings that survive a re-run, with governance actually
enforced against a declared engagement scope. That's also the differentiator that
matters for GRC-adjacent, audit-defensible use — not raw tool count.

---

## Phase 1 — Remove the automated interpretive layers (do first, low risk, high clarity)

| Item | What's wrong | Action |
|---|---|---|
| `finding_correlator.py` | Called automatically from `findings_store.py`/`ingest_promoter.py`/`hybrid.py` on every write. Auto-writes "auto-correlate same_ip=..." edges into the graph as `evidence_grade=hypothesis`, indistinguishable from real evidence unless every downstream reader remembers to check the flag. | **Remove the automatic invocation entirely.** Replace with an on-demand, read-only lookup (below). Repurpose `config/correlation_rules.yaml`'s actual match patterns (same IP, shared cookie domain, URL fanout) as the matching logic behind that lookup — don't throw the patterns away, just stop running them unasked. |
| `coverage_engine.py` (the gap calculator) | Its own docstring admits the problem: *"Cap output so noisy graphs do not drown the Commander."* It's an advisory heuristic engine pushed into every `platform_context()` read whether relevant or not. | **Remove its advisory output from `platform_context()`.** Replace with a plain, on-demand, factual coverage-check tool — no interpretation, just "what's run against X." |
| `adaptive_depth.py` | Feeds `coverage_engine.py`'s heuristics, **but** is also called directly from `recon_network.py`'s parser and `phases.py` — some of it (SPA-shell detection) is parsing-adjacent utility, not gap interpretation. | **Audit function-by-function before deleting.** Remove only what's genuinely gap-interpretation logic; keep what the parser depends on. Do not delete the file wholesale — that breaks recon parsing to fix a different complaint. |
| The demoted CLI / `agent_runner.py` path (`ENABLE_BUILTIN_AGENT`, `ENABLE_WORKFLOWS`, `workflow_runner`) | Under-invested secondary driver, off by default, silently produces worse results than the OpenCode→`platform-mcp` path — this is what was actually being benchmarked against HexStrike earlier and lost. Research in detail other drivers/implementation whether they are enough or some good implementation in agent_runner that can be encorporated with them. | **Pick one.** Dont need too many implementations when we only need one of them, so invest real engineering time to bring it to parity (same typed tools, skills, governance) or encorporate/scaffold into other implementation or only useful part of it into other implementation or delete it and standardize every demo/test/benchmark on OpenCode → `platform-mcp`. Don't leave it half-alive. Choose whichever suits best|

**Replacement tools (on-demand, LLM-initiated, deterministic, never auto-write):**

- **Related-findings lookup** — given a target/IP/host/domain/cookie, return existing
  findings that match, using the old correlation patterns as matching logic. Read-only.
  The LLM decides whether to actually link via `platform_graph_link` — nothing writes
  itself.
- **Coverage-check lookup** — given an asset, return which tools have already run
  against it. Raw `tool_coverage` fact, zero interpretation, zero "gap" language.

Both are naturally called right when the LLM stores a new finding (exactly as
described in review) or whenever it wants to check before deciding next steps — not
run automatically in the background on a schedule nobody asked for.

**Hypotheses still get stored** — that doesn't go away. `platform_think()` stays
exactly as it is: the LLM explicitly recording its own reasoning when it chooses to.
The distinction that matters: hypotheses the LLM decided to record stay; hypotheses a
background process generated without being asked go.

**Tool-surface consolidation:** collapse the ~9 memory/graph-related MCP tools down to
a lean set — `platform_context()` (leaner now, no gap advisory), `platform_memory_search()`
(recall, this is the actual "don't miss older findings in long runs" mechanism),
the two new on-demand lookups above, `platform_graph_link()` (the one explicit
write-a-relationship action), and `platform_think()` (explicit hypothesis storage).
Fewer tools to learn when to call, and the ones that remain are unambiguous about
what's fact vs. what the LLM chose to note.

---

## Phase 2 — Data-model fixes (root cause, not a bolt-on)

| Item | What's wrong | Fix |
|---|---|---|
| `tool_coverage` table | `UniqueConstraint(engagement_id, tool_name, asset)` structurally forces overwrite-only — this *is* the self-diagnosed "attempt history: overwrites → latest state, not history" gap. | Drop the unique constraint. Make it append-only (every run is a new row). Derive "latest per (engagement, tool, asset)" via a query/view. One source of truth gives current-state and full history for free — no dual-write, no drift. |
| `ingest_promoter.py`'s `_STRUCTURAL_RULE_IDS` | A hand-maintained Python frozenset deciding which regex rules to suppress when a typed parser exists — lives in Python while the rules themselves live in YAML. Silently goes stale as new parsers get added. | Move `applies_when: no_parser` into the rule definition in `ingest_rules.yaml` itself. Config becomes the actual single source of truth your architecture doc claims it is. |

---

## Phase 3 — Build the tactical-automation layer (biggest lever on raw results)

This is the actual gap that makes recon/network output trail HexStrike's, independent
of tooling or parsing quality. HexStrike's `ParameterOptimizer` and `GracefulDegradation`
are hardcoded, deterministic, and run **before** the command executes or **on** failure
— no LLM turn spent. PP's equivalent (`hint_providers.py`) only ever returns
`list[str]` — text the LLM has to notice, reason about, and act on with a fresh call.
That's a full turn spent on plumbing, every single time, on every long engagement.

**Build, mirroring HexStrike's actual pattern:**

- **`parameter_profiles.py`** — stealth/normal/aggressive flag profiles per tool in
  `kali_allowlist.json` (timing template, thread count, retry count), auto-selected
  based on target profile / detected tech / observed rate-limiting. Wired into
  `command_builder.py` so the LLM doesn't need to know good nmap/gobuster/ffuf flags
  from scratch on every call.
- **Fallback chains in `tool_execution.py`** — on tool failure, automatically retry
  with the next tool in that operation's chain (e.g. `gobuster → feroxbuster → ffuf`
  for web discovery) instead of waiting for the LLM to notice a failure and manually
  pick an alternative.

`hint_providers.py`'s role narrows to what actually needs judgment — not retry policy.

---

## Phase 4 — Governance (safety, sequence last, don't skip)

Currently a self-documented "permissive stub — approves everything." The tempting
wrong fix is a growing pile of `if tool == X and target matches Y: block` special
cases as edge cases get reported — exactly the pattern to avoid. Build **one**
evaluator that checks every built command against the engagement's declared scope +
`RulesOfEngagement` (`allow_exploitation`, `destructive_actions_allowed` — these
already exist and `exploit_pipeline.py` already reads them, check for improvememts) **before**
`build_command_for_tool` runs. One enforcement point, every current and future tool
covered automatically. The governance shouldn't block anything which should be usefull finding and exploitation, pentesting should be done smoothly and without any guardrails/restriction as good findings are found in places not much busy e.g. main domains are well protected, we have more chance of finding a vulnerability in some sister or subdomain. In short, Governance should improve the pentesting performance not degrade it.

Do this after Phase 3, not before — tightening governance first, on top of
today's under-tuned tactical layer, risks making PP's scans even more conservative
relative to HexStrike, not less.

---

## What "greater than HexStrike" actually means here

Not more tools. The axis to win on:

1. **Findings that survive a re-run** — evidence-graded, traceable back to the exact
   run that produced them. HexStrike has no equivalent; every call is stateless.
2. **Confirmed vs. speculative as a structural fact**, not a flag someone has to
   remember to check — Phase 1 makes this true by construction instead of by
   discipline.
3. **Governance actually enforced against a declared scope**, not descriptive —
   nothing else benchmarked (HexStrike, Shannon, Dark-Moon) does this properly, and
   it's precisely what matters for GRC-adjacent, audit-defensible engagements.
4. **The LLM's turn budget spent on judgment, not mechanics** — Phase 3 closes the
   actual gap causing HexStrike to currently produce more usable output per engagement
   despite PP's better architecture.

None of this requires matching HexStrike's tool count today. It requires making sure
every turn the driving LLM spends is spent deciding what's exploitable and what's worth
chasing — not re-deriving nmap flags, not manually noticing two findings share an IP,
not second-guessing whether a graph edge is fact or guess.

---

## Suggested sequencing

1. **Phase 1** — remove correlator/gap-calculator auto-behavior, resolve the CLI path's
   fate, stop advertising unwired exploit tooling. Immediate noise reduction, low risk.
2. **Phase 2** — `tool_coverage` event-log migration, YAML-driven parser-suppression.
   Small, contained, fixes self-diagnosed gaps.
3. **Phase 3** — parameter-profile + fallback-chain automation. Highest-leverage change
   for closing the actual results gap with HexStrike.
4. **Phase 4** — real governance enforcement. Safety-critical, sequenced last so it
   lands on top of a platform that's already tactically competitive.
