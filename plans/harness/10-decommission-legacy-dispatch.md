# Plan 10 — Decommission legacy dispatch + reconcile `static/`

**Baseline:** `10d13ae` · **Risk:** Medium (deletion — must confirm zero readers) ·
**Depends on:** 09 · **Size:** ~1 week.

## Why

After Plan 09 the `InvestigationDirector` + dual planner + priority engine drive everything.
The old hardcoded-dispatch machinery is now dead weight — the exact "signal → tool" family
(HexStrike/Dark-Moon pattern) we set out to beat. Remove it entirely (standing rule: when
something is replaced, delete it from the start, don't leave it as a shadow path). And decide,
finally, what happens to the `static/` design.

## What exists now (verified)
- `heuristic_engine.py` dispatch — superseded by Plan 06 priority + Plan 09 deterministic planner.
- `config/tech_dispatch.yaml` (signal→tool), `config/escalation_matrix.yaml` (fallback chains),
  `config/thinking_model.yaml` (signal classes), `config/phase_pipeline.yaml` (count triggers).
- `config/expansion.yaml` (BFS config) + `surface_expansion.py` (~600 lines) — the useful
  breadth behavior is re-homed into the deterministic planner in Plan 09 **Step 2b** (with its
  tests ported and parity proven *before* deletion). Delete here only after Plan 09 confirmed
  parity and the benchmark's `attack_surface_coverage` did not drop.
- `llmwork/static/` — the P0→P5 signal-gated engine design (NOT in the repo; a scratch "idea").

## Steps

### Step 1 — Confirm-then-delete legacy dispatch code/config
For each of `heuristic_engine.py`, `tech_dispatch.yaml`, `escalation_matrix.yaml`,
`thinking_model.yaml`, `phase_pipeline.yaml`, `expansion.yaml`, `surface_expansion.py`:
1. `grep -rn` the whole repo for readers. Plan 09 should have removed the live ones
   (`surface_expansion.py` only after its Step 2b parity check).
2. **Escalation chains** in `escalation_matrix.yaml` and the auto-fallback are genuinely useful
   *methodology* (tool-fails → try alternative). Do **not** delete the knowledge — migrate it
   into the skill/knowledge layer (Plan 08) as `capabilities`/`fallback` metadata the planner
   consults. Then delete the standalone matrix + its dispatch code.
3. **Signal→tool maps** (`tech_dispatch`, `thinking_model`) are the hardcoded-dispatch anti-
   pattern — their intent ("nginx detected → consider these tools") becomes skill retrieval
   (`find_skills(asset_type/tech)`, Plan 08). Migrate any still-valuable mapping into skill
   `capabilities`, then delete.
4. Delete the file/module only after grep shows zero readers. Remove config-loader allowlist
   entries and doc references (reconcile with the earlier docs cleanup).

### Step 2 — Reconcile `static/` (the maintainer's "idea")
- **Reject** the `static/heuristic-engine-flow.md` control flow (P0→P5 phase gating, the 45-signal
  dictionary, the P4.5 chaining engine, honeypot/scope gates) — it is the checklist-bot /
  hardcoded-dispatch model this whole program replaces, and it contradicts the direction already
  shipped.
- **Salvage its content as knowledge** (Plan 08 skills): the WSTG-mapped stream techniques
  (11 streams) and the escalation/fallback chains become skills the *reasoner* consults — never
  control flow. The **evidence-minimums** table becomes **reference knowledge** a reasoner reads
  to decide *what evidence to go gather* for a claim (it informs the human/LLM's choice of
  evidence-producing capability). It is **not** wired as a `type → required-evidence` switch in
  the finding path — Plan 03's law computes `confidence = f(evidence)` with no per-type branch,
  and the Step 7 lint gate forbids exactly such a table in code. Convert to skills/knowledge,
  cite `source: static-design`.
- Leave `llmwork/static/` as the historical artifact; do not wire it as an engine.

### Step 3 — Prune dead schemas/tools
- Remove now-unused schemas (`EscalationSuggestion`, `DispatchSuggestion`, `HybridExecutionMeta`
  if the planner no longer emits them), MCP tools that only served the old dispatch, and their
  tests. Confirm zero readers first.

### Step 4 — Final consistency pass
- `grep` the repo for references to every deleted symbol/file (code, config, docs, skills,
  AGENTS.md). Fix or remove danglers.
- Run the full benchmark + test suite; record the final scorecard vs the Plan 01 baseline.

## Reconnect
- Escalation/fallback knowledge lives in skills (Plan 08); the planner (Plan 09) consults it.
- Evidence-minimums become reference knowledge the reasoner reads when deciding which
  evidence-producing capability to invoke (Plan 03) — never a `type → required-evidence` switch.
- One driver (`InvestigationDirector`), one finding pathway (earned), one skill retrieval, one
  world model. No shadow dispatch paths remain.

## Done criteria
- `grep -rn "heuristic_engine\|tech_dispatch\|thinking_model\|phase_pipeline\|run_dispatch_stage"`
  over `backend/`, `platform-mcp/`, `cli/`, `config/` returns nothing live (docs/history aside).
- Escalation-chain and evidence-minimum knowledge is preserved as skills/validation config
  (not lost), with provenance.
- Full test suite + benchmark green; final scorecard shows the target deltas vs baseline:
  false-positive rate ↓ to ~0 on synthetic fixtures, no CONFIRMED-without-proof, attack-path
  coverage computable, redundant actions ↓.
- `static/` is documented as rejected-as-engine / salvaged-as-knowledge; nothing imports it.
