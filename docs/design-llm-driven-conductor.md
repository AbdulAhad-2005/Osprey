# Design: Pipeline-First Conductor Mode (revised — supersedes the FrontierEngine proposal)

Status: verified against code, awaiting approval to implement.

## 1. Root cause (verified in code)

The hybrid architecture the platform needs **already exists** — it is simply not the
default, and the LLM is never told it exists:

- `phase_supervisor.py` — the deterministic, LLM-free conductor: pure `decide_actions`
  (trigger-graph via `sufficiency.should_trigger`), spawns concurrent phase agents +
  the breadth-expansion job, reopens recon on new findings. = "decides WHAT/WHEN".
- `phase_agent.py` — `PhaseAgent`, an LLM ReAct loop scoped to a phase's typed tools,
  emitting visible `tool_start`/`tool_end` events. = "decides HOW".
- `platform_pipeline` (server.py:568) starts both; `platform_spawn_agent` (server.py:608)
  fans out the same PhaseAgent manually.

Confirmed defects (each verified in code):

1. `platform_set_target` auto-fires **bare** `platform_expand` (hidden worker) on every
   new engagement — server.py:439-464. The hybrid is never started by default.
2. `web_depth` stage is **ungated** — surface_expansion.py:1177-1185 runs
   feroxbuster/js_recon/well_known on any HTTP-speaking host, while `vuln_scan` is
   properly gated by `_phase_enabled` (:1237). The "feroxbuster nobody asked for"
   experience.
3. `AGENTS.md` has **zero** mentions of `platform_pipeline`/`platform_spawn_agent` —
   the LLM that free-ran via `platform_shell` was never told the hybrid exists.
4. Job store is in-memory — backend restarts kill jobs/steps.

## 2. Plan (small, targeted — no new machinery)

1. `platform_set_target` auto-fire → launch `platform_pipeline` (or surface the choice
   to the LLM) instead of bare `platform_expand`.
2. Add `phases.web_depth: false` gate to `config/expansion.yaml` — same data-driven
   pattern as `vuln_scan`; kills the scope bug at the root (inventory asks get no
   content discovery). Pipeline includes the breadth engine, so this gate is required
   together with #1.
3. AGENTS.md: add `platform_pipeline` / `platform_spawn_agent` guidance — the LLM
   reaches for the existing hybrid instead of shell-improvising. Spawned agents'
   tool events are visible via job polling.
4. Persist the job store (disk/SQLite) so restarts don't lose jobs.
5. Visibility add-on: surface `pipeline_status()` (phase_supervisor.py:307) as a
   "pipeline status" block in `platform_context` — the GUI sees agent work without
   a new tool.

## 3. Explicitly NOT doing

- Building FrontierEngine / `platform_drive` (would duplicate supervisor + agent).
- Case-bound patches (hostname blacklists, per-source retries).

## 4. Verification

- Fresh engagement: pipeline auto-starts (recon agent + breadth engine visible via
  job poll / context block); `scope=inventory` ⇒ zero web_depth steps.
- Same-prompt run: LLM uses pipeline/spawn_agent, not shell free-run.
- Backend restart mid-run: jobs survive.
