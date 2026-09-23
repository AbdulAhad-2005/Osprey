# Plan 07 — Context packet (the LLM never forgets state)

**Baseline:** `10d13ae` · **Risk:** Medium · **Depends on:** 05 · **Size:** ~1–2 weeks.

## Why

Both models agreed this is one of the most important pieces. Depth fails today because the LLM
loses state after compaction: it runs 15 tools, context compacts, and it forgets that port 8080
had Jenkins or that a JS file revealed an internal API. Raw evidence being stored isn't enough —
the LLM has to *know to look*. The fix (ChatGPT §6): a **structured state packet rebuilt every
turn from the world model**, independent of conversation history, so compaction can never drop
load-bearing state.

## What exists now (verified)
- `cli/agent/loop.py` ReAct loop + `cli/agent/compaction.py` (spill + summarize) + `context.py`
  (system-prompt assembly). Prior work removed the forced "situational brief"; the system prompt
  currently injects SESSION FINDINGS text.
- `platform_context` MCP tool assembles a briefing (jobs, phase status, deltas).
- No single, world-model-derived packet rebuilt deterministically every turn.

## Steps

### Step 1 — Define the packet
Build (deterministically, from the world model / stores — Plans 03/05/06) a compact structured
state, injected as the first system block every turn:
```
OBJECTIVE + SCOPE
WORLD MODEL SUMMARY   assets by type, key services/tech, notable relationships
COVERAGE              per-area status (from Plan 05/06), what's unexamined
TOP PRIORITIES        top-N prioritized items (from Plan 06) with one-line rationale
OPEN QUESTIONS        (Plan 05)
ACTIVE HYPOTHESES     supporting/contradicting counts
ACTIVE ATTACK PATHS   current chains + their next-needed evidence
RECENT EVIDENCE       last N tool runs (tool, target, one-line result, evidence_id)
TOOLS ALREADY RUN     (asset → tools) so it doesn't repeat
LAST ACTION / NEXT    what it just did, what it said it was about to do
CONSTRAINTS           RoE, blast-radius, rate-governor state
```
Every line traces to a store; nothing depends on conversation history surviving compaction.

### Step 2 — Rebuild every turn
- The loop rebuilds the packet each turn (cheap — it's queries over the world model). It
  replaces ad-hoc SESSION FINDINGS dumping. It is the same in the CLI and via `platform_context`
  (so an external MCP harness gets the identical state).

### Step 3 — Budget + drill-down
- The packet is summary-level and budgeted (fits comfortably in context). Every item carries an
  id so the LLM can pull detail on demand (`platform_findings`, `platform_artifact` for raw
  evidence, `get_note`, graph query). Depth = summary always present + full detail one call away.

### Step 4 — Compaction-safe
- On compaction, older turns summarize as before, but the packet is re-injected fresh from the
  world model — so compaction can never lose an asset/port/endpoint the LLM still needs.

## Reconnect
- Reads the world model (05), priorities (06), findings/observations (02/03), attack paths (05).
- The no-LLM planner (Plan 09) uses the *same* assembled state — one state, two drivers
  (ChatGPT §10: the shared-world hybrid, not "no-LLM as the headline").

## Done criteria
- After forced compaction in a replayed engagement, the packet still lists every discovered
  asset/service and the active attack paths (nothing lost).
- The LLM, given only the packet (no prior turns), can name the next sensible action on a
  fixture — proving the packet is self-sufficient.
- Benchmark: on a long fixture, `redundant_action_count` drops (TOOLS ALREADY RUN) and a
  post-compaction "forgot port 8080" regression does not occur.
