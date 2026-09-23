# Osprey Harness v2 — the "findings are earned, not manufactured" program

**Baseline:** `10d13ae` · **Author of record:** architecture review (opencode + ChatGPT discussion, alternatives teardown, direct code verification).

This is the plan to make Osprey the best autonomous pentest harness we can build:
no false positives from static interpretation, findings that are *earned* not
*manufactured*, memory that never loses evidence, and a skill system that scales
to hundreds of skills. It is **not a rewrite** — the execution kernel, MCP layer,
CLI harness, and scope/rate/audit governance are already best-in-class (HexStrike
has none of it; Strix/Swarm don't govern this well). We refactor exactly the one
layer that is on the wrong side of the line, then build the reasoning spine on top.

---

## The one principle everything follows

> **A finding is an *output* of validation/reasoning — never a *byproduct* of a tool running.**

This is the single axis on which we lose to Strix and Pentest-Swarm today, and it
is the entire false-positive problem (the "HTTP 501 became a finding" class):

- **Strix**: a finding exists only when an agent explicitly files it *after dynamic validation*. No tool output auto-becomes a finding.
- **Pentest-Swarm**: raw signals exist, but confidence is *earned* through a pipeline (classify → learning FP-cache → cross-validate → reproduce). Nothing is asserted true at parse time.
- **Current Osprey**: parsers + `ingest_rules.yaml` + `dynamic_fallback.py` mint `Finding(confidence=CONFIRMED)` straight from raw tool output. This is structurally the HexStrike/Dark-Moon family — the thing we're trying to beat.

Everything below moves Osprey from the third bucket to the first two.

## The one *law* that keeps it universal (not a pile of checks)

> **`confidence = f(evidence)`** — a finding's confidence is a pure function of the evidence
> attached to it, computed in exactly one place, branching on **nothing** about the finding's
> type/protocol/vuln-class. You raise confidence by attaching more evidence, never by asserting it.

This is why the finding pipeline is a *universal solution*, not an `if/else` or `switch` pile.
A `switch(type)` can only handle the cases someone enumerated — that is precisely how "501
became a finding." A single evidence law has **no per-case branch**, so a vuln class invented
next year is handled identically to one that ships today. The "validation strategies" are **not**
a selector the system runs by type — they are a *menu of evidence-producing capabilities* the
reasoner (LLM / planner / human) invokes like tools; the system only ever computes `f(evidence)`.
Plan 03 states this law, and a **CI lint gate forbids `finding_type ==` / `switch(type)` in the
finding/validation path** so it cannot decay back into hardcoded dispatch. Strictness lives only
where it is *governance* (scope, RoE, rate, audit, "confirmed needs a confirming evidence
record") — never where it would be *interpretation*.

---

## Verified current state (do not re-derive — confirmed against code at baseline)

- `Finding.confidence` **defaults to `CONFIRMED`** (`backend/src/osprey/schemas/finding.py:91`), across ~96 `Finding(...)` constructions in `parsers/`.
- The manufacture path is `summarize_execution` + `apply_ingest_rules`, called from `tool_execution.py`, `script_exec.py`, `shell_exec.py`, `package_install.py`.
- Full raw stdout is **already** written to disk (`write_text_artifact`) and indexed (`stdout_index.record_stdout_entry`) in `tool_execution.py:524-544`. ~80% of a replay corpus already exists.
- `FindingType.OBSERVATION` already exists (`finding.py:33`); a `_NARRATIVE_TYPES` set already exists — the observation concept is partially present.
- Parsers: **13 modules / ~68 `parse_*` functions** (not "71 files" as the discussion claimed).
- `cli/agent/flows.py` **does not exist** but is imported at `cli/commands/slash.py:980` and `:1066` → `/agent` and custom-command expansion crash with `ImportError`. Live bug.
- Skill index (`knowledge_browser.py`) is a **flat `name — description` list capped at 200** (`skills_index_text`). 78 skills today; will not scale to 800+.
- Legacy dispatch still live: `heuristic_engine.py`, `config/{tech_dispatch,escalation_matrix,thinking_model,phase_pipeline}.yaml`, `surface_expansion` vuln dispatch gated behind `include_vuln_dispatch=False`.

---

## KEEP (already ≥ the alternatives — do not touch the internals)

Execution kernel (`tool_execution.py` scope/rate/cache/audit/budget), MCP tool layer
(`platform-mcp/server.py`), CLI harness (`cli/agent/loop.py` ReAct loop + compaction),
engagement graph schema, artifacts/stdout-index storage.

## REFACTOR decisively (the disease)

The interpretation→finding pathway: parsers become **structural extractors → Observations
only**; findings become **earned** (explicit filing OR graded validation pipeline);
`confidence` default flips to `hypothesis`.

## ADOPT from the field

Strix: explicit-file-after-validation, specialized subagents, resumable snapshots.
Swarm: learning FP-cache, earned-confidence pipeline, reproduction gate, pheromone-decay
prioritization. Anthropic: `SKILL.md` format (description-as-retrieval-hook + MITRE/NIST
tags) for a skill system that scales.

## REJECT

The `static/` P0→P5 signal-gated engine and HexStrike's hardcoded `IntelligentDecisionEngine`
— both are the hardcoded-dispatch family we are trying to beat. `static/`'s *content*
(WSTG techniques, escalation chains, evidence minimums) is salvaged as **knowledge** in Plan 08,
never as control flow.

---

## Execution order

Each step is independently shippable **except 02+03, which ship as one atomic unit**
(see below). "Independently shippable" means: after that unit lands, you have a working
system that is better than before and whose benchmark delta is recorded.

| # | Step | Solves | Depends on |
|---|------|--------|-----------|
| 00 | [Quick fixes](00-quick-fixes.md) | `/agent` crash, `confidence` default | — |
| 01 | [Replay & benchmark harness](01-replay-benchmark-harness.md) | "are we actually better?" is unanswerable | 00 |
| 02+03 | [Evidence/Observation layer](02-evidence-and-observation-layer.md) **+** [Earned-finding pipeline](03-earned-finding-pipeline.md) — **one atomic unit** | parsers manufacture findings; 501-as-evidence; single-source CONFIRMED | 00, 01 |
| 04 | [Learning FP-cache](04-learning-fp-cache.md) | the same false positive recurs forever | 02+03 |
| 05 | [World model + attack paths](05-world-model-and-attack-paths.md) | checklist bot; no cross-observation reasoning | 02+03 |
| 06 | [Prioritization engine](06-prioritization-engine.md) | binary coverage; finding-count triggers | 05 |
| 07 | [Context packet](07-context-packet.md) | LLM forgets state after compaction | 05 |
| 08 | [Skill system at scale](08-skill-system-at-scale.md) | flat 200-cap index; adding more skills degrades it | — |
| 09 | [Dual-mode planner](09-dual-mode-planner.md) | two entry points, signal-gated engine | 05,06,07 |
| 10 | [Decommission legacy dispatch](10-decommission-legacy-dispatch.md) | dead/duplicate hardcoded dispatch | 09 |

> **Why 02+03 are inseparable:** Plan 02 removes *all* finding creation on the tool path,
> and Plan 03 is what re-adds it (as earned findings). Shipping 02 alone would leave a
> product that produces **zero findings** and starves every finding reader
> (`report_outline`, `handoff_dossier`, `operator_recall`, `exploit_pipeline`). They are one
> refactor split across two files for readability, not two independently releasable steps.

**Measurement gate:** after 03, 04, 06, and 09, re-run the Plan 01 benchmark and record
false-positive rate, validated-finding count, and coverage. No step is "done" until its
benchmark delta is recorded — that is how we avoid the discussion's unfounded
"we'll be best in 14 weeks" claim.

## Two architectural invariants (every step must honor both)

These are non-negotiable across the whole program. If a step's design violates either, the
design is wrong — not the invariant.

**I. The CLI is the primary harness; the MCP layer serves *external* harnesses.**
Every capability this program adds must be drivable from the CLI, through the existing
in-process MCP bridge (`cli/agent/tools.py`) and the `InvestigationDirector` (Plan 09) — never
via a backend/MCP-only path the CLI can't reach. `file_finding`, `promote_observations`,
`find_skills`, the FP-cache marks, the context packet, the planner: all reachable and operable
from the terminal. The MCP surface stays a *mirror* of the same capabilities for OpenCode/Claude
Desktop/etc., not a superset. Done-criteria that name an MCP tool must also work from the CLI.

**II. No LLM is required — the deterministic engine is the floor, the LLM is depth on top.**
Every step must degrade cleanly to a working no-LLM path:
- Structural extractors (Plan 02) are always-on; LLM observation extraction is an *enhancement*.
- `promote_observations` + safe evidence-producing capabilities (Plan 03) earn findings with no LLM;
  `confidence = f(evidence)` is the same function in both modes — only the evidence *menu* is smaller.
- `DeterministicPlanner` (Plan 09) drives the `InvestigationDirector` over the same world model,
  priority, coverage, and context packet the LLM would use.
- Without an LLM the system still runs a systematic, governed investigation and presents raw
  evidence + earned findings to the human; it simply does not add the LLM's cross-observation
  depth. It must never *require* the LLM to function, and must never *manufacture* a finding to
  compensate for the LLM's absence.

The benchmark (Plan 01) runs both modes; a step that regresses the no-LLM path is not done.

## Standing rules (from the maintainer, in force for every step)

1. No patching around a symptom. Refactor the mechanism; delete the old implementation from the start.
2. If something is removed, remove **all** traces and reconnect anything that breaks.
3. Never trust a comment/docstring/other-LLM prose as evidence — trace real control flow or run it.
4. Prioritize simplicity and long-term maintainability over cleverness.
5. Honor the two architectural invariants above (CLI-primary, no-LLM-floor) in every step.
