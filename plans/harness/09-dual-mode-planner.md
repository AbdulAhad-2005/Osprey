# Plan 09 — Dual-mode planner (one world, deterministic or LLM driver)

**Baseline:** `10d13ae` · **Risk:** High · **Depends on:** 05, 06, 07 · **Size:** ~2–3 weeks.

## Why

This is the "one harness, one execution path" the maintainer has wanted from the start, done
correctly. ChatGPT §10 framed it best: the win is not "no-LLM," it's that a **deterministic
reasoner and an LLM reasoner drive the same world model, same evidence, same execution** — either
can run, both can contribute. This replaces the two current entry points (LLM-via-supervisor and
deterministic-via-surface-expansion) and the signal-gated `heuristic_engine`.

## What exists now (verified)
- Two entry points sharing one kernel + blackboard (opencode's "three pipelines" was wrong):
  `phase_supervisor.run_pipeline()` (spawns agents) and
  `surface_expansion.run_expansion_to_fixpoint()` (calls `heuristic_engine.run_dispatch_stage`
  only when `include_vuln_dispatch=True`, default False).
- `heuristic_engine.py` dispatches on finding counts / signals — the model Plan 06 retires.
- Subagent spawn exists (≤4 workers).
- Agent modes via `.osprey/agents/*.md` (fixed in Plan 00) give per-agent tool scope.

## Design

```
                 WORLD MODEL (Plan 05) + PRIORITY (Plan 06) + CONTEXT PACKET (Plan 07)
                                    │  same inputs
                    ┌───────────────┴───────────────┐
                    ▼                                ▼
        DETERMINISTIC PLANNER                  LLM REASONER
        decide_next_action():                 reads context packet, proposes action
          pick highest-priority item,         (interpret, hypothesize, pivot, chain)
          consult find_skills() for            files findings after validation
          the technique, emit Action           (Plan 03 file_finding)
                    └───────────────┬───────────────┘
                                    ▼
                          ACTION RESOLVER  (validate scope/RoE/blast-radius — exists)
                                    ▼
                          EXECUTION KERNEL (exists, unchanged)
                                    ▼
                          EVIDENCE → OBSERVATIONS (Plan 02) → WORLD MODEL ↺
```

## Steps

### Step 1 — One `Planner` protocol
- Define `decide_next_action(state) -> Action | None` where `state` is the assembled world
  model + priorities + coverage + questions + attack paths (the Plan 07 packet, structured).
- Two implementations: `DeterministicPlanner` (picks top-priority item, uses `find_skills` to
  choose the capability + methodology for it) and `LLMPlanner` (the packet → LLM → proposed
  Action). Same input type, same output type.

### Step 2 — `InvestigationDirector` (replaces the two entry points)
- One loop: assemble state → `planner.decide_next_action()` → action resolver → kernel →
  evidence → observations → world-model update → repeat. Terminates on: no action above
  priority threshold, budget exhaustion, or objective met.
- `phase_supervisor`'s driving loop folds into this directly (it already just spawns agents on
  finding state).

### Step 2b — Extract `surface_expansion`'s breadth behavior deliberately (do NOT hand-wave)
`surface_expansion.py` is ~600 lines of battle-tested breadth logic, and its tests were already
flaky in a prior session — "folds into the planner" undersells the risk. Treat this as its own
migration with the specific behaviors enumerated and individually re-homed, each behind a
benchmark check, not a rewrite-from-memory:
- **Enumerate first** every capability surface_expansion provides: fixpoint "keep expanding
  while new assets appear," netblock/CIDR expansion, sister/affiliate-domain discovery, PTR /
  reverse-DNS expansion, per-asset dedup, and the frontier/visited bookkeeping.
- **Re-home each as deterministic-planner behavior**: "expand while new high-priority assets
  appear" becomes the planner's normal loop (a newly discovered in-scope asset is just a
  high-`novelty`/`coverage_importance` item — Plan 06 — that the planner naturally picks next).
  The netblock/sister/PTR expanders become capabilities the planner selects, not a bespoke BFS.
- **Port the tests first.** Bring `surface_expansion`'s existing tests over (and fix the flaky
  ones) as director tests *before* deleting the module, so parity is proven, not assumed.
- **Only then** delete `surface_expansion.py` (Plan 10 confirms zero readers). Losing its
  breadth would be a real capability regression — the benchmark's `attack_surface_coverage`
  metric must not drop across this step.

### Step 3 — Hybrid (both contribute)
- With an LLM: `LLMPlanner` drives; the `DeterministicPlanner` runs as a **safety net** that
  flags high-priority coverage gaps the LLM ignored (surfaced into the context packet:
  "deterministic planner notes: auth on api.x untested, priority 0.8"). LLM can act or dismiss.
- Without an LLM: `DeterministicPlanner` drives; findings are only what safe validation
  strategies earn (Plan 03); unexplained observations are presented to the human.

### Step 4 — Parallel investigation
- When the priority queue has independent high-priority items (no shared prerequisite), the
  director fans out specialized subagents (Plan 08 skill-scoped), bounded by the parallelism
  config. This is Pentest-Swarm's concurrency, governed by our existing budget/rate layer.

### Step 5 — Retire `heuristic_engine` dispatch
- Delete `heuristic_engine.run_dispatch_stage` and its signal/finding-count logic (Plan 06 +
  the deterministic planner subsume it). Remove `include_vuln_dispatch` gating — the director
  decides vuln work by priority, not a boolean.

## Reconnect
- `job_store` spawn path, MCP `platform_pipeline`/`platform_spawn_agent`, CLI agent loop all
  call the `InvestigationDirector` (one path). Confirm no caller still reaches the old
  `run_pipeline`/`run_dispatch_stage` directly.
- Full legacy config/module removal happens in Plan 10 (this plan stops *calling* them; Plan 10
  deletes them once nothing references them).

## Done criteria
- One `InvestigationDirector` loop; both planners implement one protocol; grep shows no live
  caller of `heuristic_engine.run_dispatch_stage` or the old dual entry points.
- No-LLM run on a fixture completes a systematic investigation (breadth + safe validation) with
  zero manufactured findings.
- LLM run on the same fixture reaches ≥ the deterministic coverage AND advances at least one
  attack path the deterministic planner wouldn't (proving the hybrid adds depth).
- Benchmark recorded for both modes; hybrid ≥ either alone on validated-finding count.
