# Strategic Direction: Where the Pentesting Harness Stands & How to Move Forward

## Context

You asked three things, really: (1) is our architecture *right* — we deliberately merged
two "roads" (an MCP tool-surface for external harnesses like OpenCode/Claude Code, **and**
our own self-harness) and you fear that binding them is a mess; (2) where do we stand against
Strix (a harness) and HexStrike (an MCP tool surface); (3) where do skills live in the
pipeline, how do we let people add custom skills per phase, and how do we stop the LLM from
ignoring them — including whether to pull in the 818 Anthropic cybersecurity skills.

I reverse-engineered the codebase and verified everything below against the code (not the
docs — several docs are stale). Two of your working assumptions turned out to be wrong, and
correcting them changes the strategy. This document is the direction; §4 is the concrete
first build.

---

## 1. Where we actually stand (verified against code, not docs)

| | **HexStrike** (`other tools/hexstrike-ai`) | **Strix** (`other tools/strix`) | **Us** |
|---|---|---|---|
| What it is | MCP + Flask tool server, ~22K LOC. **No LLM harness** — the connecting model drives. | A real autonomous harness: generalist agent in a Docker sandbox. | Both: a governed MCP tool-surface **and** a self-harness, over one shared conductor. |
| Tool model | ~150 typed tool wrappers | **Raw `shell` + `proxy` + `agent_browser`** — the agent runs tools itself; no typed catalog | ~90 **typed, governed** tools + `platform_shell`/`platform_script` escape hatches |
| Black-box domain input | Yes | **Yes** — `strix --target example.com` / `192.168.1.42` / `https://app.com` are first-class | Yes (`platform_set_target`) |
| Memory | None (stateless tools) | Notes/todo + agents-graph, run-scoped | **Durable typed evidence-graded finding graph in Postgres** (per engagement) |
| Multi-agent | No | `agents_graph` | `phase_supervisor` conductor + `platform_spawn_agent` |
| Needs a paid brain | No (you bring one) | **Yes** — Strix *is* the brain | No for MCP mode; optional key (free/local OK) for self-harness |
| Autofix / SARIF / CI | No | Yes (`apply_patch`, SARIF, GitHub Actions) | No |

**Two assumptions corrected:**
- **"Strix can't do black-box / domain-only testing."** False — verified in
  `strix/interface/cli_args.py`: it accepts URL, repo, local dir, OpenAPI, Postman, **bare
  domain, and IP**. Its real difference from us is *how*: it gives the agent a raw shell +
  intercepting proxy + browser in a throwaway sandbox and lets it improvise, with **no typed
  tool catalog and no durable evidence graph**. That is precisely our opening, not our
  weakness.
- **"HexStrike can do black-box but isn't a harness."** Correct — it's a tool surface. We
  already *are* HexStrike-plus: same typed-tool idea (we harvested its `build_command`
  recipes) **plus** governance + typed findings + a conductor. We are strictly ahead of
  HexStrike architecturally.

**Our actual differentiator (keep betting on this):** *typed, governed tools feeding a
durable, evidence-graded engagement graph.* Strix's autonomy produces raw-shell noise and
run-scoped memory; we produce structured, severity-clamped, provenance-carrying findings that
survive context limits and restarts. Neither reference tool has this. **Do not copy Strix's
raw-shell design** — it would throw away the one thing that makes us elite.

---

## 2. Is the "two roads together" approach right? — Yes, and it is not a mess

Your instinct that *binding two brains into one pipeline* would be a mess is correct. But the
codebase already solved it the right way, and the fix is live (verified):

**One Conductor, Two Executors.**
- The **conductor** (`phase_supervisor.py` + `sufficiency.py`) is **LLM-free shared state**:
  phase sequencing (recon always first; vuln/exploit unlock on evidence thresholds),
  loop-back on new assets, the full tool catalog, per-phase skills, and the shared blackboard
  (`findings_store` + `engagement_graph`). It decides *what/when*, never *how*, and never
  calls an LLM itself.
- **Executor A** = an external harness (OpenCode/Claude Code/any MCP client) using its own LLM
  and its own subagents. Reaches the conductor read-only via `platform_pipeline`. **No key
  needed — this is your affordable default.**
- **Executor B** = our own CLI/GUI self-harness: the backend drives a phase-agent ReAct loop
  with a user-supplied key (any LiteLLM provider, **including free/local models**).

The two executors are **interchangeable, never concurrent** — they consume the *same*
conductor, so behaviour can't diverge. The "two brains colliding" bug (a backend key silently
spawning a second brain inside an MCP session) was already found and deleted:
`start_pipeline()` is now permanently read-only (verified — returns `readiness_only`,
`_PIPELINES` registry gone). **So the thing you feared already can't happen.** The reason to
keep both roads is real: Executor A is free (bring your own harness), Executor B is the real
harness when no external brain is present.

> **The real risk is not "binding" — it is capability drift between the two paths.** Today the
> two executors already deliver *skills* differently (§4). Every new capability must land in
> the shared conductor/blackboard, or the two roads slowly diverge. That is the maintainability
> rule for the next 5 years, and §4 + §6 enforce it.

---

## 3. Your decision: build Executor B into a full self-hosted interactive commander harness

**The vision (clarified):** Executor B is *not* the `scan --target X` batch command — that's
just one entry. It is a **self-built interactive pentest harness**: a chat interface + a
dashboard where a user types free-form prompts exactly like they do in OpenCode, except the
brain is *our* harness running **whatever LLM key the user configures** (Claude / DeepSeek /
GPT / Groq / local Ollama). This is the "elite complete harness" end goal, self-hosted and
key-agnostic.

**What already exists (foundation is real, verified — not vaporware):**
- **Any-provider LLM core** — `llm_service.py` is LiteLLM (Claude/DeepSeek/GPT/Groq/Ollama);
  key passed per-call; default is a *free* Groq model. "Any user, any key" is already the
  architecture.
- **Streaming chat API** — `POST /api/v1/agent/chat/stream` (SSE) already emits live
  `tool_start`/`tool_end`/`phase_triggered`/`pipeline_tick` events — the exact backbone a chat
  UI + live dashboard consume.
- **Multi-turn plumbing** — `run_agent(prompt, conversation_history, commander_note)` threads
  history to the phase agent; interactive terminal chat loop exists in `cli/main.py`.
- Conductor, phase agents, shared blackboard, and the single tool kernel — all reused as-is.

**What's genuinely missing (the real build — focused, not a rewrite):**
1. **A true Commander loop.** The weak point today: `phase="full"` runs the batch pipeline to
   fixpoint and returns a *canned summary* (not conversational); other phases run a single
   scoped burst. Need a top-level agent that takes any message, holds the **full tool catalog +
   conductor readiness + skills**, decides to *answer* / *run a tool* / *launch or steer the
   pipeline as a background job*, streams it, then waits for the next message. It must
   **kick the conductor off in the background and keep chatting** — never block for the 3600s
   fixpoint — so the user can steer mid-run ("hit the sister domains harder") exactly like
   OpenCode. The Commander *owns* the conductor; it does not *become* it.
2. **Server-side conversation sessions** — persist chat per engagement in Postgres (today
   `conversation_history` only lives in the request), so CLI and dashboard share one thread.
3. **The dashboard** — none exists (`dashboards/` is empty; the old report-only React app is
   being removed). Build a thin one: chat pane, live event stream (events already emitted),
   findings/graph view, engagement + job status (`pipeline_status` exists), settings.
4. **Per-user key configuration (UI + storage)** — core takes any key, but it comes from
   backend `.env` today; add a Settings surface to pick provider + paste key.

**Simplicity guardrails (5-year lens):** build the Commander loop **once** — CLI chat and
dashboard chat both hit the same `/agent/chat/stream`, never two loops. Stay **local-first,
single-user** ("any user configures any key" = the person running it sets their key in
Settings); do **not** add multi-tenant auth until there's a concrete reason — it's the biggest
long-term maintenance trap and isn't needed to be elite. The new code is: Commander agent +
conversation store + thin frontend + key-settings endpoint. Everything else is reuse.

### 3a. Commander ↔ conductor wiring: connect, never fork

The Commander is a **second executor over the existing conductor** — structurally identical to
OpenCode (backend Commander : Executor B :: AGENTS.md-guided OpenCode : Executor A). It does
**not** get its own pipeline (that would duplicate `phase_supervisor` sequencing/sufficiency/
loop-back — the exact diverging-roads trap). It relates to the conductor as a background job it
launches and steers:
- answers/one-off tool → runs directly through `execute_tool_request`
- "pentest fully" → `launch_pipeline` **as an asyncio background task** (`run_pipeline` is
  already built fire-and-forget with `on_event`), streams events, stays conversational
- "hit the sisters harder" → `spawn_agent` (targeted, via `job_store`)
- "stop" → `stop_pipeline` (already cancels active jobs)

Same conductor state, same sufficiency thresholds, same tool kernel as Executor A — so the two
brains cannot diverge. Add a `commander` phase reusing `phase_agent.run()`'s ReAct loop with the
full catalog + `skills/commander/` + readiness snapshot + the three control tools above. Repoint
the default chat from `phase="full"` (batch) to `phase="commander"`; keep `phase="full"` as an
explicit tool/flag, not the chat brain.

### 3b. Frictionless: kill the mandatory `set_target` ceremony

The **engagement** (durable per-target store) is the differentiator — keep it. The **explicit
`platform_set_target`-first ceremony is unnecessary friction** and today it's a hard wall: the
chat endpoint returns `_NO_TARGET_MSG` with no engagement+no target, and `run_agent(phase="full")`
errors "target must be bound first." Fix: binding becomes **lazy, implicit, Commander-owned** —
`set_target` is an internal tool, never a user prerequisite. Per-turn context resolution:
1. target named in the message → auto-bind/create that engagement, then act
2. no target + active conversation engagement → use it
3. neither → one short clarifier, not a wall

Rule: **there is always a working engagement, but the user never creates one explicitly** — like
a coding agent inferring the working project. Delete both walls; the full-loop path binds *then*
launches. (Plumbing exists: `_prompt_has_scannable_target`, `compile_engagement_for_target`,
`extract_target`, kernel seed-injection at `tool_execution.py:168`.) Don't build a special
"scratch engagement" type yet — the three rules cover ~95%.

**One challenge, then I follow your call:** you also said you can't always afford paid keys.
These reconcile — Executor B runs on **free/local models via the existing LiteLLM
`llm_service.py`** (Ollama/local, or free-tier providers). So "develop the harness strongly"
does *not* mean "depend on paid APIs." I'll design it around cheap/local models as a
first-class target, not an afterthought. State this explicitly so it stays true under
maintenance.

**What "complete and strong" requires (the gap vs Strix, mapped to what we already have):**
1. **Reliability of the ReAct loop** — turn budgeting, tool-error recovery, and honest
   stopping. We already have `execution_recovery.py`, `escalation_matrix.yaml` auto-fallback,
   and the `sufficiency` readiness signal. Can build the loop around these; do **not** add a
   "forced continuation" gate (explicitly rejected before — it's unenforceable and was deleted;
   trust the readiness signal instead).
2. **Web-testing muscle** — Strix's edge is its intercepting **proxy** + browser for request
   capture/replay. We have `browser_flow`/`browser_scrape` and web tools but no request-replay
   proxy. This is the biggest genuine capability gap for black-box web pentesting.
3. **Skills actually steering the agent** — see §4. Right now Executor B truncates the whole
   phase dir to 6000 chars; that must become description-indexed and phase-anchored.
4. **Reporting parity** — we have `report_generator`/`markdown_report`/`report_outline`; add
   framework mapping (MITRE/NIST from §5) so reports read as elite, and consider SARIF for CI.
5. **Local-model robustness** — smaller models need tighter tool schemas and shorter prompts;
   the skills redesign (§4) directly helps by sending only relevant skills, not whole dirs.

This is a multi-phase effort (§7), sequenced after the skills layer because §4 is the
foundation both executors stand on.

---

## 4. Skills — where they live, how they reach the pipeline, and custom skills (FIRST BUILD)

This is the concrete near-term build and it directly answers "where do we put skills."

### The current weakness (verified)
- Skills are `skills/<phase>/*.md`, loaded by **directory name**. They have **no frontmatter
  and no per-skill description** (they start with `# Title`).
- The index the LLM sees (`knowledge_browser.list_skills`) is only
  `{path, phase, title, chars}` — **no description**, so the model can't triage which skill to
  open and often opens none.
- **Two delivery paths diverge:**
  - Executor A (MCP): **pull-based** — `platform_context` shows a name/path index; the LLM
    must call `platform_skills(path=…)`. **Ignorable** → your exact fear, confirmed real.
  - Executor B (backend): **push-based** — `phase_agent.py:493` injects the *entire* phase dir,
    truncated to 6000 chars. Blunt, and breaks on large skill sets.

### The design (one mechanism, both executors)
1. **Adopt the SKILL.md frontmatter convention** (same as Anthropic's 818 skills and Strix's
   `load_skill`): every skill gets `name`, `description`, `phase`, `tags` (optional `mitre`,
   `nist`). This is the single highest-leverage change — a *description* is what lets any LLM
   decide relevance. Convert our existing skills by adding frontmatter (title → name, first
   paragraph → description); no content rewrite.
2. **One registry keyed by phase + description.** Extend `knowledge_browser.list_skills` to
   parse frontmatter and return `description`. Both executors read this one function — kills
   the two-path divergence.
3. **Anchor skills to the conductor's phase boundary — this is "where in the pipeline."** The
   conductor already knows the active phase and readiness. Surface *"skills for the ACTIVE
   phase"* as `name — description` lines inside the `platform_context` / phase-readiness packet
   the LLM reads every turn. So recon skills appear during recon, exploit skills the moment
   exploit unlocks. The model still *pulls* the full text on demand (`platform_skills(path=…)`)
   — but it can no longer *miss* that a relevant skill exists, because the description is in
   front of it at the right phase. (We cannot *force* an external harness to read a skill — no
   MCP hook can veto a turn; this was proven and is why we make them impossible to overlook
   rather than mandatory.)
4. **Custom skills = drop-in, zero code.** A user adds `skills/<phase>/my-skill.md` with the
   frontmatter (or `skills/custom/*.md` carrying a `phase:` field) and it's auto-indexed and
   surfaced at that phase. Document this as the extension contract. This is the "anyone can add
   skills for any phase" capability you want. Also add it at an appropriate place e.g. readme for users to know how they can add their custom skills.
5. **Executor B stops dumping whole dirs** — inject only the active phase's skill *descriptions*
   + the one or two the agent pulls, matching Executor A. Fixes the 6000-char truncation and
   helps small/local models.

Net: skills live **in `skills/<phase>/`, indexed by description, surfaced by the conductor at
the active phase, pulled on demand, identical for both executors, and extensible by drop-in.**

### Critical files (skills build)
- `skills/**/*.md` — add YAML frontmatter (`name`, `description`, `phase`, `tags`).
- `backend/src/pentest_platform/services/knowledge_browser.py` — parse frontmatter; return
  `description` in `list_skills`; the one registry.
- `backend/src/pentest_platform/services/skills_loader.py` — description-aware loading;
  remove whole-dir concatenation.
- `backend/src/pentest_platform/services/phase_agent.py:493` — inject descriptions for the
  active phase, not the truncated dir.
- `backend/src/pentest_platform/services/phase_supervisor.py` / `commander_context.py` —
  add active-phase skill descriptions to the readiness/context packet.
- `platform-mcp/server.py` — `platform_context` shows active-phase skill descriptions;
  `platform_skills` unchanged (still the pull tool).

---

## 5. Anthropic Cybersecurity Skills — adopt format, import the red-team subset, keep the mappings

818 skills in exactly the SKILL.md format §4 adopts, each tagged with **MITRE ATT&CK + NIST
CSF**. You said we're red-team/pentest — so:
- **Do not bulk-import.** Most are defensive/DFIR/compliance (detecting/hunting/analyzing-logs/
  CMMC). Bulk import would bloat every prompt and mismatch our phases.
- **Import the offensive subset**, mapped to our phases: `exploiting-*`, `abusing-*`,
  `performing-*` (attack ones), `testing-*`, plus recon-relevant `analyzing-*` /
  `scanning-*`. Their `scripts/` are runnable via `platform_script`.
- **Keep their MITRE/NIST tags** and carry them onto our findings → report coverage against a
  framework. That is a concrete "elite report" differentiator Strix/HexStrike don't have.
- Because §4 makes skills description-indexed and phase-anchored, importing more skills does
  **not** bloat prompts — only descriptions for the active phase are ever shown.

---

## 6. Simplicity & maintainability (5-year lens) — verified findings

Good: the ~3,500 lines of rejected "gap-tracking" machinery (`open_loops`,
`finalize_readiness`, `coverage_engine`, `hypothesis_engine`, `adaptive_depth`,
`phase_reflection`, `dispatch`) **are actually deleted**. Follow-through was real.

**The per-call advisory-nudge layer (verified live, superfluous).** The same "steer the LLM
by attaching soft text to responses" philosophy you already rejected in its *hard* form
(forced-continuation gate) survives in *soft* form: every tool call in
`tool_execution.execute_tool_request` bolts on a stack of "never forces, never blocks" hints —
`consult_tracker`/`build_memory_note` (*"N tools since you consulted memory"*),
`_attach_parallel_note`, `_attach_recovery_hints` (text), `next_hint`/soft-next-hints,
`escalation_suggestions` text. Their own docstrings admit they're advisory — the exact premise
your memory note proved false (advisory text can't make a harness act). On strong brains they're
token bloat on every call; on weak models they duplicate the skills+readiness layer, which is
surfaced once per turn in the right place. **Cut them and their config knobs**
(`consult_drift_threshold`, `parallel_soft_note`, the `next_hint` plumbing); move any genuinely
useful methodology into skills (§4). **Keep the deterministic *actions*** — `_maybe_auto_fallback`
(re-runs the top escalation), `_maybe_auto_scan_network_vulns`, shadow-failure downgrade,
`_attach_digest` (parsed-output compression, not a nudge). Then audit the adjacent hint cluster
(`agent_assist.py`, `platform/adaptation.py`, `platform/hint_providers.py`,
`platform/orchestration_hints.py`, `parallelism_config.py`) — verified by name/role, not yet
line-by-line — separating nudge-text from real Executor-B behavior before cutting.

Remaining dead/duplicate cleanup (verify each before cutting, per your no-patch/delete-dead rule):
- **`workflow_runner.py` + `workflows/`** — `ENABLE_WORKFLOWS=false`, `workflows/` dir is
  empty, yet the code is still reachable via the `hybrid.py` endpoint (lists/runs zero
  workflows). Dead surface — remove endpoint + runner.
- **`backend/src/pentest_platform/platform/*` (~1570 LOC)** — *partially* live: `handoff`,
  `adaptation`, `run_context`, `situational_context` feed Executor B; the context-duplication
  parts are gone. Don't blanket-delete (the memory note overstates this) — audit the four live
  modules for overlap with `commander_context`/`context_delta` and consolidate the context
  builders into one.
- **Two context builders** — `commander_context.py` (330) vs `session_context.py` (164) vs
  `context_delta.py` (94): confirm they aren't computing overlapping packets for the two
  executors; unify onto the conductor packet from §4.
- **Stale docs** — `ARCHITECTURE.md` still says web/vuln/exploit are "planned," but those MCP
  tools exist now (sqlmap/dalfox/nuclei/metasploit are registered). Refresh or archive the
  stale docs so the next maintainer isn't misled (you already flagged docs as unreliable).

~78K LOC of Python is a large surface for a small team — the governing rule going forward:
**new intelligence goes into the LLM-free conductor + description-indexed skills, not into new
per-executor services.** That keeps both roads in sync and the surface flat.

---

## 7. The plan — three workstreams, sequenced

Your three stated priorities map to three workstreams. **A first** (it shrinks and clarifies the
surface B and C build on); **B and C** then build the elite frictionless conductor and the own
harness on the cleaned base. Each step ends green (`pytest` + `ruff`), nothing half-migrated
(delete-in-the-same-pass rule).

### Workstream A — Slim & clean the loop (do first)
Remove what the settled direction makes unnecessary, so nothing new is built on cruft.
- **A1. Per-call nudge layer (§6).** Delete `consult_tracker` + `build_memory_note`,
  `_attach_parallel_note`, `_attach_recovery_hints` (text), `next_hint`/soft-next-hints,
  `escalation_suggestions` text, and their config knobs. Keep the deterministic actions
  (`_maybe_auto_fallback`, `_maybe_auto_scan_network_vulns`, shadow-downgrade, `_attach_digest`).
- **A2. Hint-cluster audit (§6).** One verified pass over `agent_assist.py`, `platform/adaptation.py`,
  `platform/hint_providers.py`, `platform/orchestration_hints.py`, `parallelism_config.py` —
  separate nudge-text from real Executor-B behavior; cut the former.
- **A3. Dead surface.** Remove `workflow_runner.py` + empty `workflows/` + its `hybrid.py` route;
  unify the overlapping context builders (`commander_context`/`session_context`/`context_delta`)
  onto the one conductor packet.
- **A4. Docs truth-pass.** Refresh/archive `ARCHITECTURE.md` (web/vuln/exploit are built now, not
  "planned"); it must describe the Commander + two-executor reality.
- Files: `services/tool_execution.py`, `services/consult_tracker.py`, `services/parallelism_config.py`,
  `services/workflow_runner.py`, `api/v1/endpoints/hybrid.py`, `platform/*`, `docs/ARCHITECTURE.md`.

### Workstream B — Conductor: elite & frictionless
Make the shared conductor smarter and remove the binding ceremony — benefits **both** executors.
- **B1. Frictionless implicit binding (§3b).** Delete the `_NO_TARGET_MSG` wall and the
  `phase="full"` "must bind first" error; make `set_target` Commander-owned with the three-rule
  per-turn resolution. Files: `api/v1/endpoints/agent.py`, `services/orchestrator.py`,
  `services/target_utils.py`.
- **B2. Skills layer (§4).** SKILL.md frontmatter + one description-indexed registry
  (`knowledge_browser.list_skills`) + conductor-anchored surfacing at the active phase +
  custom drop-in; stop dumping whole dirs in `phase_agent.py:493`. Foundation for the Commander
  and for the Anthropic import. Files: `skills/**`, `services/knowledge_browser.py`,
  `services/skills_loader.py`, `services/phase_agent.py`, `services/phase_supervisor.py`,
  `platform-mcp/server.py`.

### Workstream C — Own harness: the Commander (the main build)
The self-hosted interactive commander — your in-house OpenCode.
- **C1. Commander agent + wiring (§3, §3a).** Add the `commander` phase (reuse `phase_agent.run()`
  loop + full catalog + `skills/commander/` + readiness + `launch_pipeline`/`spawn_agent`/
  `check_readiness`/`stop_pipeline` tools). Repoint default chat to `commander`; `run_pipeline`
  launches as a background task and streams events. Files: `services/orchestrator.py`,
  `services/phase_agent.py` (or a thin `commander_agent.py`), `api/v1/endpoints/agent.py`.
- **C2. Conversation sessions.** Persist chat per engagement (Postgres) so CLI + dashboard share
  one thread; replace the not-good REPL default and the batch-`scan`-as-default. Keep one thin
  scriptable/CI door that runs the Commander non-interactively.
- **C3. Key settings.** Settings surface + storage so any user picks provider + pastes key
  (LiteLLM core already provider-agnostic). Files: `api/v1/endpoints/config.py`, `models.py`.
- **C4. Dashboard = seed of the proper GUI.** Thin frontend on the existing SSE: chat pane, live
  tool/agent event stream, findings/graph view, engagement + job status (`pipeline_status`),
  settings. Rebuild `dashboards/`. **The eventual "proper GUI" is this iterated, with zero backend
  rewrite** — it's just a richer client of the same `/agent/chat/stream` + REST surface (web, or a
  local-first Electron/Tauri desktop shell).

**GUI-ready guardrail (holds across A–C):** the system is API-first — the Commander, conductor,
kernel, and state all live server-side; every front door (CLI, dashboard, proper GUI) is a client
of the same endpoints. **No intelligence in the client, ever** — the GUI only renders and sends
messages; all decisions/tool-calls/state stay server-side. To keep the proper GUI purely additive,
bank these in C1–C3: structured SSE for *every* live change (tool + agent events already emit;
ensure findings/graph updates emit too), conversation persisted (C2) so the GUI can render/resume
history, real stop/steer endpoints (`stop_pipeline` exists), and key settings behind an endpoint
(C3). If these hold, CLI and GUI stay perfectly in sync because they share one brain.

### Then — capability parity (after the harness stands)
- Anthropic red-team skills import + MITRE/NIST → findings/report coverage (§5).
- Web request-replay **proxy** (biggest black-box gap vs Strix), local-model robustness, reporting/SARIF.

Sequencing rationale: A removes cruft so B/C aren't built on it; B's skills + frictionless
binding are what the Commander (C) stands on; parity work is meaningless until the harness exists.

---

## Verification

- **Skills build:** add frontmatter to a few skills; call
  `GET /api/v1/capabilities/skills-index` and confirm `description` is returned; drive a fresh
  engagement in both Executor A (MCP `platform_context`) and Executor B
  (`pentest scan --target X`) and confirm the active phase's skill descriptions appear in the
  turn context, and that a dropped-in `skills/recon/custom-test.md` shows up with no code
  change. Run `pytest` (baseline is 163 passing + 4 known-unrelated failures).
- **Dead-code cut:** `ruff --select F401,F821,F841` after each removal; `pytest` green.
- **Positioning claims:** re-confirm anytime by reading `strix/interface/cli_args.py` (target
  types) and `hexstrike-ai/hexstrike_server.py` (no LLM loop) — both cited here from the code.
