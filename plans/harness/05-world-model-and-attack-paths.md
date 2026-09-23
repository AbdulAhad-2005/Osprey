# Plan 05 — World model as the hub + attack-path reasoning

**Baseline:** `10d13ae` · **Risk:** Medium · **Depends on:** 02 · **Size:** ~2–3 weeks.

## Why

ChatGPT's §8/§12 is the sharpest strategic point in the whole discussion: the center of the
system should be a **world model** of the discovered environment, and the most valuable output
is **attack-path reasoning** — the relationships *between* observations, which don't map to any
single coverage category. A coverage-only system becomes "the world's most thorough checklist
bot"; an attack-path system finds the public-API → internal-ref → cross-boundary chains that
matter.

We already have most of the substrate: the engagement graph. This plan re-centers it on
observations (post Plan 02) and adds attack paths as a first-class object.

## What exists now (verified)
- `engagement_graph.py` — typed asset nodes + named edges, currently built by auto-linking from
  *findings*. It is already a projection (not canonical), which is correct.
- Node types cover domain/subdomain/ip/port/service/url/technology/etc.
- After Plan 02, the graph should be fed by **observations**, not verdicts.

## Steps

### Step 1 — Re-source the graph from observations
- `engagement_graph.ingest_observation(obs)` replaces `ingest_finding` auto-linking as the
  primary builder. Assets/edges are evidence-backed: every node/edge carries the
  `observation_id`(s) that assert it.
- **Confidence is derived from the *current* set of supporting and contradicting observations —
  it can go up OR down.** Do **not** make it monotonic-rise (the old graph behavior). A
  monotonic floor is incompatible with two things this plan needs: the decay model in Plan 06,
  and conflict resolution in Step 2a. When an observation is contradicted or its supporting
  evidence decays, the node's confidence must be able to fall. Recompute confidence from the
  live observation set on each `ingest_observation`, don't ratchet it.
- Remove the auto-linking that created edges *without* an observation backing them (the
  "linked unrelated hosts on a shared CDN IP" class). An edge must cite an observation.

### Step 2 — World model query surface
- `world_model` view over the graph + observations answering the questions the planner/LLM need:
  `assets(type)`, `assets_with_incomplete_investigation()`, `related(asset)`,
  `unexplained_observations()` (observations not yet connected to any asset/hypothesis).
- This is a read model over the graph, not a new store.

### Step 2a — Conflicting observations (no special resolver, but must be represented)
- When two observations assert different values for the same slot (port 443 → `nginx` from
  nmap vs `Apache` from whatweb), the model keeps **both**, each with its own confidence, and
  marks the slot `conflicted`. It does **not** silently pick one or overwrite.
- `world_model` surfaces the conflict (e.g. `service@443: nginx (0.7, nmap) ⚠ Apache (0.6,
  whatweb)`) so the context packet (Plan 07) shows it and the LLM/human resolves it, or a later
  observation breaks the tie. This is the "handled by normal operation" that only works once
  Step 1's confidence is non-monotonic — it is why the monotonic rule had to go.

### Step 3 — Attack path as a first-class object
- `AttackPath`: an ordered chain of `(observation|asset|hypothesis)` steps with an
  `edge rationale` per hop and a `status` (hypothesized → investigating → validated → dead).
- `attack_path_store` with `propose`, `advance`, `attach_evidence`, `list_active`.
- Example the model must represent: `public API endpoint → internal endpoint reference (obs) →
  different authz boundary (obs) → object identifier (obs) → cross-user access (hypothesis →
  validated finding)`.

### Step 4 — Questions & hypotheses (the reasoning scaffold)
- `question_store` (open questions) + `hypothesis_store` (active hypotheses with
  supporting/contradicting observation ids). These are cheap and the LLM writes them freely
  (no approval). They are the bridge between "unexplained observation" and "attack path."
- The deterministic planner (Plan 09) can auto-raise methodology questions for an asset with
  incomplete investigation; the LLM raises novel ones.

### Step 5 — Persistence & concurrency (new stores)
- `attack_path_store`, `question_store`, `hypothesis_store` are durable (Postgres tables +
  a batch-mode Alembic migration, tested SQLite+PG like the prior migrations) — not in-memory.
- **Concurrency:** Plan 09 fans out parallel subagents that all write observations / advance
  attack paths / answer questions against shared state. Every write on these new stores (and
  on `observation_store` from Plan 02) must be atomic under concurrent writers, matching the
  guarantee `findings_store` already provides. A subagent's write must be visible to another
  subagent's next `world_model` read / priority recompute. This is a store-implementation
  requirement, not an architecture change — but it must be stated so parallel investigation
  (Plan 09 Step 4) is correct rather than racy.

## Reconnect
- Findings (Plan 03) link to the attack path / hypothesis they validated.
- Coverage (Plan 06) is computed over the world model, not from finding counts.
- Context packet (Plan 07) serializes the world model + active attack paths + open questions.
- `graph_query` MCP tool now returns observation-backed nodes/edges + attack paths.

## Done criteria
- Every graph edge cites ≥1 `observation_id`; no edge exists without evidence backing.
- An `AttackPath` can be proposed spanning ≥3 observations across different categories and
  advanced to a validated finding on a synthetic fixture built for it.
- `unexplained_observations()` returns observations not yet tied to an asset/hypothesis (the
  raw material for curiosity-driven investigation).
- Benchmark: `attack_path_coverage` metric becomes computable; a planted multi-step chain in a
  synthetic fixture is discoverable via attack-path advance (not just per-category coverage).
