# Plan 06 — Prioritization engine (multi-factor, decay-aware)

**Baseline:** `10d13ae` · **Risk:** Medium · **Depends on:** 05 · **Size:** ~1–2 weeks.

## Why

Today "what to do next" is driven by finding-count phase triggers
(`config/phase_pipeline.yaml`, `live_hosts >= 3 → vuln`) and binary coverage. That is both
too rigid (ChatGPT §7: checklist bot) and too primitive. The two best systems prioritize
dynamically:
- Pentest-Swarm: **pheromone decay** — every blackboard finding has a per-type base weight and
  half-life; downstream agents act on hot signals, stale ones fade (`config/pheromones.yaml`).
- ChatGPT §11: a single `heat` scalar is too primitive; use a **multi-factor priority**.

We take the good part of both: decay as *one* input to a multi-factor score, not the whole
intelligence.

## What exists now (verified)
- `config/phase_pipeline.yaml` finding-count triggers; `surface_expansion` BFS; coverage is
  binary (started/partial/complete) in prior work.
- No decay, no multi-factor priority, no per-observation/asset scoring.

## Steps

### Step 1 — Priority model
Implement a scoring function over world-model items (assets, observations, questions, attack
paths) — ChatGPT §11's factors, each a small pure function:
```
priority(item) =
    objective_relevance      # matches the engagement objective/scope
  + evidence_strength        # how well-supported by observations
  + novelty                  # unexplained / newly discovered
  + potential_impact         # from methodology knowledge for this asset type
  + relationship_centrality  # graph centrality — hub assets score higher
  + unexplained_behavior     # anomalies vs expected
  + validation_potential     # can we cheaply validate it?
  + coverage_importance      # is this a gap the objective needs?
  - cost                     # tool time / noise budget
  - repetition               # already-run tool+params on this asset
  - risk                     # blast radius / RoE distance
```
Each factor reads the world model / methodology / audit log. Weights live in a small config
(`config/priority.yaml`) — tunable, but the *factors* are code (they're system primitives,
not pentest knowledge).

### Step 2 — Decay as one input
- Observations/candidates carry a `first_seen`/`last_corroborated`; `novelty` and
  `evidence_strength` decay over time so stale state fades and fresh state stays hot.
- The half-life is driven by a **`volatility` property of the observation** (how fast that kind
  of state actually changes — an open port is durable, a transient probe result is not), not by
  a hardcoded `type → half-life` switch. Seed the defaults from Pentest-Swarm's half-life table
  in `config/priority.yaml`, but it is a *tunable prioritization default*, not a truth rule:
  it only affects *what to look at next*, never whether a finding is real, and the benchmark
  tunes it. This is prioritization scoring, not per-type interpretation — it does not fall under
  Plan 03's no-per-type law (which governs *confidence*), but it deliberately avoids a rigid
  type table for the same reason.
- Decay feeds the score — it is not the score.

### Step 3 — Coverage becomes a factor, not the driver
- Coverage (over the world model, Plan 05) contributes `coverage_importance` — "the objective
  wants auth tested and we haven't" raises priority. But an unexplained high-centrality
  observation can outrank a coverage gap. Coverage answers "what's unexamined"; priority answers
  "what's worth doing next." Both feed the planner (Plan 09).

### Step 4 — Retire finding-count phase triggers
- `phase_pipeline.yaml`'s `live_hosts >= 3 → vuln` style triggers are replaced by: a phase/area
  is "worth entering" when the world model has items whose priority for that area crosses a
  threshold. No hardcoded counts. (Full planner in Plan 09; this plan lands the scoring the
  planner consumes.)

## Reconnect
- Planner (Plan 09) consumes `priority()` to pick the next action for both no-LLM and LLM modes.
- Context packet (Plan 07) shows the top-N prioritized items so the LLM sees what the
  deterministic engine thinks is hot.
- Benchmark: `redundant_action_count` should fall (repetition penalty); `time_to_first_validated
  _finding` should improve (impact/validation_potential rank real leads first).

## Done criteria
- `priority(item)` is computed from the listed factors, weights in `config/priority.yaml`.
- Removing `phase_pipeline.yaml` count-triggers does not regress the benchmark (the planner
  enters an area on priority, not counts).
- A synthetic fixture where the interesting lead is a low-count-but-high-centrality asset:
  the planner reaches it before exhausting a high-count-but-boring area.
