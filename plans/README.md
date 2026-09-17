# Osprey Refactor Plan — Unification & De-scoping

**Baseline commit:** `d7a4594` (all file:line anchors below are against this commit; re-verify before editing — the codebase moves).

**Goal of this plan set.** Strip the platform down to a single, honest, un-caged execution surface: raw tool output reaches whoever is driving (LLM, external harness, or a future no-AI engine) without premature truncation; findings are labelled by what was actually proven, not by what a scanner pattern-matched; and rigid mechanisms that block a capable driver are turned into advisory signals or removed outright. This is the cleanup that must land **before** the larger "one harness / implement the pentest flow" build — it removes the scattered, half-built, or misleading machinery that build would otherwise have to carry forward.

## Non-negotiable working rules (apply to every plan file)

1. **No patching.** Fix the mechanism, not the reported symptom. Never wrap an issue in a regex / if-else / special-case bound to the one case that surfaced it. If an implementation is poor, delete it and replace it — do not layer new code around it.
2. **Remove all traces.** When something is removed, remove *every* reference: the definition, the imports, the call sites, the config keys, the DB column (+ migration), the MCP tool registration, the schema field, the tests, and the docs/skills that mention it. A grep for the removed name after the work must return only this plan and git history.
3. **Reconnect what breaks.** Removing a thing usually severs a connection something else relied on. Every plan file has a **Reconnect** section listing the consumers that must be reworked so the system is whole again — never leave a stub, a dead import, a `None` fallback that silently changes behaviour, or a "temporarily kept for compat" shim.
4. **One pass per file.** If two workstreams touch the same lines (e.g. evidence-grade removal and parser-severity honesty both edit `parsers/vuln.py`), they are merged into one plan so those lines are rewritten once, correctly, not twice.
5. **Verify, don't trust.** Every claim in these plans was checked against real control flow at `d7a4594`. The executor must re-confirm each anchor (grep/read) before editing and STOP + report if reality has drifted from what the plan describes.

## What is being removed (decided)

| Thing | Why | Plan |
|---|---|---|
| `evidence_grade` / `EvidenceGrade` / `clamp_claim_severity` / `default_grade_for_type` | 2-D grade×severity system causes false "confirmed/critical" labels; being deferred to a future compliance mode. Severity becomes 1-D, assigned honestly by parsers. | 02 |
| Crown jewels (`crown_jewels.py`, `platform_crown_jewels`, `platform_tag_asset`) | Arbitrary pre-computed ranking; the driver prioritises from ports/services/findings itself. | 03 |
| Chaining engine, signal vocabulary, honeypot gate, scope-validation gate (design docs) | LLM-invented scoring/gates not grounded in real sources; chaining is the driver's job via raw output + `additional_args`. | 08 |
| The 5 scattered stdout truncation caps | Collapse to one honest, tool-aware policy so exploitation output (sqlmap dumps, ffuf) reaches the driver. | 01 |
| Situational brief + escalation hints inside tool results (backend agent path) | Belong in `platform_context`, not stapled to every tool result. | 07 |

## What is being kept (decided — do NOT remove)

Phase progression P0→P5 · recon tool sequences · escalation *chains* (naabu→masscan→nmap tool fallback on failure) · "No Exploit, No Report" discipline · breadth-before-depth · `additional_args` passthrough · memory ingestion · `platform_artifact` · `platform_context` · `claim_severity` (as the sole, 1-D severity signal).

## Execution order & dependency graph

```
01 truncation-unification        (independent; highest user-visible value; do FIRST)
02 evidence-grade-removal        (independent; large; includes parser-severity honesty)
        │
        ├──> 04 exploit-status-truthfulness   (needs 02: "proven" redefined without grade)
        └──> 07 tool-result-and-context-trim  (coordinates with 01; report changes need 02)
03 crown-jewels-removal          (independent of 01/02)
05 rigid-wrappers-to-advisory    (independent; small)
06 fanout-consolidation          (independent; medium)
08 heuristic-docs-descope        (docs only; independent; lowest risk)
```

Recommended landing sequence: **01 → 02 → 04 → 03 → 07 → 05 → 06 → 08.** 01 and 02 are the two that matter most and are independent, so they can proceed in parallel by two people; everything else can follow in any order respecting the arrows above.

## Status table (executor updates this)

| # | Plan | Risk | Depends on | Status |
|---|---|---|---|---|
| 01 | truncation-unification | M | — | TODO |
| 02 | evidence-grade-removal (+ parser severity) | **H** | — | TODO |
| 03 | crown-jewels-removal | M | — | TODO |
| 04 | exploit-status-truthfulness | M | 02 | TODO |
| 05 | rigid-wrappers-to-advisory | L | — | TODO |
| 06 | fanout-consolidation | M | — | TODO |
| 07 | tool-result-and-context-trim | M | 01, 02 | TODO |
| 08 | heuristic-docs-descope | L | — | TODO |

## Considered and rejected

- **Removing `evidence_grade` AND replacing it with nothing, leaving severity un-clamped but parsers unchanged.** Rejected: that keeps the optimistic parser defaults (sqlmap-detection→CRITICAL) which are the actual false-positive source. Grade removal is only safe if parser severity honesty (folded into plan 02) lands in the same pass.
- **"Just raise the 2500 cap to 50000 / remove it" (opencode's phrasing).** Refined: the cap at `platform-mcp/server.py:1076` was added deliberately because unbounded stdout filled external-harness context on long sessions (see the comment at `server.py:1072`). Blindly removing it regresses that. Plan 01 makes it tool-aware and unified, not merely bigger.
- **Keeping crown jewels but fixing the silent ≤0 drop.** Rejected by the maintainer: the whole ranking is being removed; the driver prioritises itself.
