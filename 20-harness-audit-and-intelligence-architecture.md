# Plan 20 — Harness Audit & Intelligence Architecture

This plan is the output of a full-codebase audit. It records **every issue found**,
the **fix** for each, and a **target architecture** for how Osprey's pentesting
intelligence (skills, config rules, memory) should be structured so both the
deterministic floor and the LLM brain get maximum leverage from it.

It is deliberately split into four parts that can land independently:

- **Part A — Dead code & competing paths** (cleanup; low risk, do first)
- **Part B — Memory & evidence correctness** (the real bugs behind FP / fake
  promotion / looping)
- **Part C — The architectural reframe** (floor vs. brain; what "intelligence
  under the harness" actually means — the lens for everything else)
- **Part D — Intelligence-source architecture** (skills + config + memory as one
  structured, cross-linked knowledge system — the "elite harness" target)

---

## The one idea that frames everything (read first)

Osprey has **two flows**, and the word "intelligence" has been applied to both,
which is the root cause of several issues below:

- **LLM flow** — [`cli/agent/loop.py`](../../cli/agent/loop.py) `Runner`, driven by
  `LLMDriver`. The **model is the intelligence**; everything else is scaffolding.
  This is "Claude Code for pentesting" and it is the right design.
- **Deterministic flow** — [`investigation_capabilities.py`](../../backend/src/osprey/services/investigation_capabilities.py)
  `list_step()` + `DeterministicInvestigationDriver`. This is a **priority-ranked
  opportunity enumerator** driven by data in `config/*.yaml`.

**The axis is deterministic-vs-judgment, NOT thin-vs-smart.** An earlier draft of
this plan said "keep the engine a thin, dumb floor" — that was the wrong axis and
is corrected here. The deterministic engine must be a **procedural decision engine
that runs every *applicable* battle-tested check for what it has observed, across
every in-scope asset, and explains the gaps** — token-free, the engine's job, never
the LLM's. Concretely that means: enumerate subdomains, resolve and port-scan and
version in-scope hosts, surface CVE *candidates* for detected versions, JS-recon and
content-discover live web hosts, check dangling CNAMEs for takeover, harvest OSINT —
*where each step applies to that asset* (e.g. no WordPress check on a non-WordPress
host). "Complete" is **applicable-and-explained, not literally every-tool-on-every-
asset** (see Part C and E3). "Dumb" applies only to *judgment* (no open-ended
reasoning), not to *scope*. Part E audits where the engine currently stops short.

- **Judgment** — reading an odd response and chasing it, chaining findings into an
  exploit, deciding an ambiguous param is worth manual testing, novel methodology.
  This needs the LLM. It is the *only* thing the LLM should be spending tokens on.

**Decision:** "Intelligence under the harness" (the operator's "blanket over a
person" concept) = one engine that (a) executes the full battle-tested methodology
deterministically and token-free, (b) is supervised by the LLM at bounded
checkpoints when a key is present, (c) hands a human a complete, actionable
recon+vuln-surface dossier even with no LLM at all. The harness guarantees four
things so the brain spends tokens only on judgment:

1. Run the **complete** mechanical methodology for free (deterministic engine →
   no tokens on any battle-tested step, from httpx to version→CVE mapping — Part E).
2. Refuse to let any brain file junk (evidence gates — Part B).
3. Remember what has been tried so no brain loops (durable attempt memory — Part B).
4. Surface the right priorities and the right methodology at the right moment
   (intelligence-source architecture — Part D).

The existing `SupervisedDeterministicDriver` ("the person runs itself; the LLM is
the blanket that checks in at bounded checkpoints",
[`drivers.py:546`](../../cli/harness/drivers.py)) is the correct embodiment of
this and should be the headline run mode once Parts A/B/E land — but only once the
deterministic methodology it supervises is actually complete (Part E).

---

## Guarantees this plan makes — and the three it does NOT

The plan must not ship checks that **pass under some conditions and fail under
others, or falsely tag things**. So the guarantees are stated precisely, and the
over-promises an earlier draft made are explicitly withdrawn.

**What the plan guarantees:**
- **Determinism of verdicts (precisely bounded).** A verdict is a pure function of
  the **recorded evidence set, its recorded timestamps, and the check version** —
  not of wall-clock time, of which brain ran it, or of the order evidence happened to
  be *fed* to the evaluator. It is **not** a claim that re-scanning a live target
  returns the same thing (targets change), nor that temporal order is ignored: the
  recorded *sequence* of an original confirmation and a later recheck is itself
  evidence and does matter (B4). So: same recorded evidence (with its timestamps) +
  same check version → same verdict, every time. Flaky/condition-dependent
  confirmation is a bug.
- **Traceable evidence.** Every finding links to the exact recorded tool output and
  the specific claim that output establishes (B0). You can always answer "why does
  the system believe this?"
- **Explicit uncertainty.** Every finding carries an honest, visible
  (severity × confidence) pair — "CRITICAL (hypothesis)" is never shown as
  "CRITICAL" (B3). Unknown/unreachable is stated as such, never silently resolved.

**What the plan does NOT promise (withdrawn over-claims):**
- NOT "false findings are impossible." We make false *confirmations* hard and
  *traceable*, and keep everything reversible — we do not claim they can't happen.
- NOT "memory problems are impossible." We remove the specific, verified issues
  (B0–B5) and bound growth; we do not claim a clean bill forever.
- NOT "complete = everything." Completeness is "every *applicable* configured check
  for what was observed, across in-scope assets, with gaps explained" — never
  "every tool on every asset" (Part C / E3).

## Three design pillars (from the operator's intent)

1. **The deterministic engine is real procedural intelligence** (Part C) — it decides
   from observed evidence via explicit procedures, token-free. Not a dumb floor.
2. **The LLM is heavily used, not sidelined.** The substrate exists to make the LLM
   *maximally effective*, not to replace it. The LLM drives typed tools directly,
   gets the full skills library ranked and **pushed into context at the moment its
   trigger appears** (D3), supervises the deterministic run and can take over
   completely at any checkpoint or on operator command, and owns all creative work:
   judgment, chaining, bespoke exploitation, business-logic and auth testing. An
   unverified-but-promising lead is routed *to the LLM to investigate* (B3) — using
   the LLM is the point, not the fallback. **"Greatly used" means *useful* use, not
   constant use (per review):** skills are all *discoverable* and the *relevant* ones
   injected within a context budget — never the whole library; and a lead pulls the
   LLM **once per material change**, not repeatedly on the same unchanged lead. So the
   defect condition is precise: the LLM is idle while a promising lead exists *that has
   budget, no in-flight job already covering it, and has not already been analyzed
   unchanged* — re-triggering on an unchanged lead is itself a defect (it is the
   looping B1 exists to kill).
3. **The operator can extend the deterministic intelligence themselves.** Everything
   the engine "knows" is data the operator can author: recon stages (`expansion.yaml`),
   dispatch checks (`tech_dispatch.yaml`), tool catalogs (`*_tools.yaml`), priority
   weights (`priority.yaml`), skills (`skills/*.md`), custom modes/commands
   (`.osprey/agents|commands`). **Honest boundary (per review — "everything without
   code" overpromises):** *composing existing tools/checks into a new check* is
   config-only; a *genuinely new testing technique* may need a small script or adapter
   — which is supported through the **existing `platform_script`/`custom_tools.yaml`
   path** (the script self-reports evidence the same way every tool does), not by
   editing the Python core. Either way it must be documented, validated, and
   hot-reloadable (Part G), so a pentester grows the engine's procedural intelligence
   without touching core code.

## Resolved decisions & deployment model (settled with the operator)

1. **Deployment: single-node, local-per-user — but architected SaaS-ready.** Each
   user runs their own backend on their own machine. v1 is single-node; teams/SaaS
   come later, so make the two choices that would otherwise be a rewrite *now*
   (per-connection engagement binding; anti-loop state readable from the durable DB,
   not only in-memory) and defer everything else (RBAC, multi-tenant, shared
   fp_cache) until the teams phase.
2. **Scope default: conservative** (seed domain + its own subdomains only). Sister
   domains, full-port sweeps, and nmap-vulners stay **opt-in** / surfaced-for-
   operator-approval. Part E's completeness fixes still land, but the *aggressive*
   ones ship **off by default**, behind an explicit operator flag or an
   authorized-scope allowlist — never auto-on. (Part E1.1 version→CVE via
   searchsploit is read-only and safe, so that one IS on by default; the intrusive
   breadth is not.)
3. **Interfaces: CLI stays the main harness; the dashboard is a co-equal second
   interface** (Part F), both clients of **one shared runtime built first** (per
   review — the runtime + run-ownership land before either interface is wired, so
   the dashboard never becomes a second orchestration loop). The operator asked for
   dashboard capability — submit a target from it, the engagement **runs in the
   background**, and it shows **all data + asset/attack-path graphs** live — but it
   is an *addition* to the CLI, not a replacement for it. Neither is "primary"; they
   observe/drive the same runtime.
4. **Audience: solo pentesters/researchers first**, teams later — consistent with
   (1). Optimize v1 for a single local operator's depth and token-free autonomy; no
   collaboration/RBAC work yet.

### How it will be used (the local, dashboard-driven model)

One local process (the FastAPI backend) runs on the user's machine and serves both
the dashboard and the API. Tools execute either in a local Kali container or
natively on the host (already supported — README Path A/B/C). The user:

1. Opens the local dashboard (e.g. `http://localhost:8000/...`), **types a target**,
   and starts a run — or does the same from the CLI; both hit the same backend.
2. The engagement **runs in the background**: the deterministic engine executes the
   full battle-tested methodology token-free; if an LLM key is configured it
   supervises at checkpoints and handles judgment/exploitation.
3. The user **watches live** — asset graph, services/versions→CVEs, findings with
   evidence grade, the unverified-scanner-claims section, and the ranked
   manual-verify queue — all streaming over the existing event bus (SSE).
4. With **no LLM key**, the same run still completes and ends in the human-actionable
   dossier (Part E3); the dashboard is then a review-and-work surface.

Because one local backend can run several engagements concurrently (dashboard + CLI,
or multiple dashboard tabs), **per-connection engagement isolation (B5 fix 2) is
required even in the single-node build** — it is not a SaaS-only concern.

## Part A — Dead code & competing paths

### A1. Confirmed dead code (no production caller)

| Symbol | Location | Evidence | Fix |
|---|---|---|---|
| `InvestigationDriver.decide()` / `DeterministicInvestigationDriver.decide()` / `Decision` dataclass | [`drivers.py:190,263,514`](../../cli/harness/drivers.py) | `drive()` selects inline via `max(launchable, key=priority)` ([`drivers.py:416`](../../cli/harness/drivers.py)); `.decide()` has zero callers. | Delete `decide()`, the base `NotImplementedError` stub, and `Decision`. |
| `decide_actions()` + `SpawnAction` | [`phase_supervisor.py:47`](../../backend/src/osprey/services/phase_supervisor.py) | Only referenced by `test_phase_supervisor_decide_actions.py`. No runtime caller — the conductor is read-only. | Delete both + the test (or demote to a doc note that the conductor is read-only). |
| `PipelineState` | [`phase_supervisor.py:36`](../../backend/src/osprey/services/phase_supervisor.py) | Zero callers. | Delete. |
| `_spawn_agent_job()` | [`phase_supervisor.py:253`](../../backend/src/osprey/services/phase_supervisor.py) | Zero callers. | Delete. |
| `_maybe_auto_scan_network_vulns()` | [`phase_supervisor.py:192`](../../backend/src/osprey/services/phase_supervisor.py) | Only a **comment** references it ([`tool_execution.py:674`](../../backend/src/osprey/services/tool_execution.py)). Its logic is **duplicated live** as `SCAN_NETWORK_VULNERABILITIES` in [`investigation_capabilities.py:614`](../../backend/src/osprey/services/investigation_capabilities.py). | Delete the dead copy; keep the live one; fix the stale comment. |

**Net:** `phase_supervisor.py` collapses to what it actually is — a read-only
phase-readiness snapshot + brief provider. Rename its remaining surface to make
"read-only" structural (e.g. `phase_readiness.py`).

### A2. Competing / contradictory sources of truth

- **The recon subagent brief contradicts AGENTS.md.**
  [`_SUBAGENT_BRIEFS["recon"]`](../../backend/src/osprey/services/phase_supervisor.py#L77)
  tells a spawned agent to *"Drive platform_investigation_step → platform_investigation_execute
  one bounded decision at a time."* AGENTS.md operator card **point #4** says the
  opposite: *"If you're about to call platform_investigation_step, stop — call the
  typed tool you actually want instead."*
  **Fix:** make the briefs and AGENTS.md draw from one source. The brief handed to a
  CLI-spawned worker should match the doctrine the top-level operator follows
  (drive typed tools directly). If `platform_investigation_step/execute` is truly
  the no-LLM-only path, no LLM-driven brief should ever recommend it.

- **Methodology is encoded twice** — once as hard rules in `list_step()`, once as
  prose in AGENTS.md / skills — with nothing keeping them in sync. The brief
  contradiction above is this failure already happening. Part D addresses the
  structural fix (cross-linking); short term, add a test that asserts no
  LLM-facing brief mentions `platform_investigation_step`.

- **`platform_spawn_agent`** ([`agent_runner.py`](../../backend/src/osprey/services/agent_runner.py))
  is a third execution host (backend-driven single agent, needs the backend's own
  `LLM_API_KEY`) overlapping the CLI's own `spawn_subagents`. Keep it (it's the
  documented fallback for harnesses with no subagent mechanism) but **document the
  decision tree** in one place so it's clearly a fallback, not a parallel primary.

### A3. Repo hygiene (blocks a clean release tag)

This is about **release packaging, not deletion** (correction per review — do not
delete the operator's own work).
- **Safe to remove** (temp/scratch build artifacts): `tmp_cisa_book.txt` (~1 MB),
  `inspect_cisa_book.py`, `tmp_iso_inventory.py`, `.codex-build/`, `.codex-finalizer/`.
- **Keep — exclude from the release package, never delete:** `deliverables/`
  contains the operator's FYP proposal decks and Osprey presentations;
  `Prep-final-staging/` is the operator's own ISO-27001 study material. These are
  not product code but they are the operator's work — `.gitignore` / packaging
  exclusion only, and confirm before touching either.
**Fix:** gitignore the scratch artifacts, exclude presentation/study dirs from the
release tarball/image build, and verify the *packaged* artifact is clean — not by
deleting anything from the working tree.

---

## Part B — Memory & evidence correctness

**Context — what is solid, and the one claim an earlier draft overstated.** Two
things are genuinely solid and must not be re-solved: (a) `promote_observations()`
(the "truth from counts" launderer) was deleted
([`finding_pipeline.py:211`](../../backend/src/osprey/services/finding_pipeline.py)),
so nothing auto-mints a finding from a scanner count; (b) findings are *created*
exactly one way — `file_finding`, with no `confidence=` parameter (confidence is
computed, not asserted), and structural facts are rejected
([`finding_pipeline.py:107`](../../backend/src/osprey/services/finding_pipeline.py)).
There is no bypass **on finding creation**.

**But an earlier draft said this made fake confirmation "architecturally
impossible" — that is wrong, and B0 below is the correction.** Confirmation
*strength* is still gameable: grounding proves an excerpt is real, not that it
entails the claim; and ATTESTATION reaches CONFIRMED with no grounding at all. So
the remaining work is **five** items (B0 is new and is the most important).

### B0. Confirmation is not entailment-checked (the fake-confirm hole) — highest priority

**Symptom:** a finding can reach the highest-trust tier (CONFIRMED) without
evidence that actually proves it ("promoting fake things" in its one surviving,
real form).

**Root cause — two distinct holes, both verified in code:**
1. **Grounding proves existence, not entailment.** [`evidence_grounding.py:78`](../../backend/src/osprey/services/evidence_grounding.py)
   `_shares_substring` accepts a REPRODUCTION/VERIFICATION claim if any contiguous
   20-char run of the claim text appears verbatim in recorded output. That proves
   the quoted text is *real*; it does **not** prove the text *supports the finding's
   claim*. A genuine `Server: Apache/2.4.49` banner grounds a finding titled "RCE
   via CVE-2021-41773" — the banner proves the version, not exploitability. (The
   module's own docstring describes exactly this scenario as the bug it closes, but
   the implemented check only verifies the excerpt is real, not that it entails.)
2. **Attestation is a free pass to CONFIRMED.** `file_finding` exempts ATTESTATION
   from grounding ([`finding_pipeline.py:173`](../../backend/src/osprey/services/finding_pipeline.py)
   `_GROUNDED_KINDS` = {REPRODUCTION, VERIFICATION}) and [`confidence.py:40`](../../backend/src/osprey/services/confidence.py)
   counts ATTESTATION as a CONFIRMING kind — with **nothing enforcing that the
   attestation came from a human.** An LLM/agent can attach an attestation record
   and reach CONFIRMED on its own say-so.

**Fix — a concrete, LIMITED design (not another scoring system, per the review):**
- **Each supported check records exactly what it established** — the specific claim,
  the target, and the supporting evidence excerpt. Confirmation applies *only to that
  recorded claim*. An interpretation that goes beyond it (banner → "RCE applies")
  stays **unverified** until its own check runs. There is no scoring model, no
  weights — a check either recorded a result entailing *this* claim or it did not.
- **CONFIRMED** requires either (a) such a check result that entails this finding's
  claim, or (b) genuine **human** provenance.
- **Human provenance must come from a dedicated operator-confirmation channel the
  agent's tool surface cannot reach.** This is the subtle part on a *local, no-auth*
  box (deployment decision 1): the agent runs *as the same OS user*, so "came from the
  local account" does NOT prove a human did it. The distinction must be mechanical, not
  identity-based: a confirm action exists only as an out-of-band UI affordance — a
  dashboard "Confirm finding" button or an interactive CLI prompt — that is **not
  registered as a platform/MCP tool** and cannot be invoked through the agent's
  function-calling surface. The platform stamps `human=true` from *that channel only*,
  never from tool arguments. An agent/LLM has no code path to set it.
- Agent/tool attestation never confirms: it is a **ceiling of not-higher-than-LIKELY**,
  and the actual level is still whatever the evidence earns (HYPOTHESIS with none) —
  "not confirmed" never means "automatically LIKELY."
- Keep the existing real-excerpt grounding as a *necessary* gate; the entailment /
  operator-provenance requirement is the *sufficient* condition added on top for the
  CONFIRMED tier.

This is the real, bounded guarantee: **traceable, claim-scoped confirmation** — not
"fake findings are impossible."

### B1. Looping — the failure-cap persistence asymmetry (highest-impact bug)

**Symptom:** the harness re-runs things that already failed/empty-returned,
especially after a restart ("looping on unneeded things").

**Root cause:** in [`investigation_capabilities.py`](../../backend/src/osprey/services/investigation_capabilities.py),
`_successful_opportunity_ids` ([:331](../../backend/src/osprey/services/investigation_capabilities.py#L331))
recovers completed work from the **durable** `scan_run_store`, but
`_failed_opportunity_ids` ([:271](../../backend/src/osprey/services/investigation_capabilities.py#L271))
reads **only** the in-memory `job_store` (`_MAX_JOBS_KEPT = 200`, wiped on
restart). So the "stop re-offering after 2 identical failures" cap evaporates on
every backend restart or after 200 jobs. A chronically-failing opportunity (no
egress for gau, a dead external API) is re-offered and re-fails forever.

Separately, the **LLM loop stall guard is session-scoped** — `self._call_outcomes`
([`loop.py:250`](../../cli/agent/loop.py)) resets each session, so across `/resume`
or a new chat the LLM has no durable "already ran this, it was empty" and relies on
*choosing* to call `platform_attempts` (pull-based).

**Fix — use the store that already exists; do NOT build a second memory system
(per the review).** `scan_run_store` is already DB-backed and already persists
`status`, `error`, `request`, `results_log`, and `result`
([`scan_run_store.py`](../../backend/src/osprey/services/scan_run_store.py)), and
already exposes `successful_investigation_opportunity_ids`. So:
1. Make `scan_run_store` the **single source** for retry decisions: add the mirror
   `failed_…`/`exhausted_…opportunity_ids` read, so both success and failure come
   from the same durable history (removes the asymmetry). Extend the store only
   where a direct tool call or outcome isn't recorded yet.
2. **Keep outcome types distinct** — successful-check-with-no-match, tool failure,
   timeout, interrupted. "Already tried" must *prevent waste*, not *permanently
   hide work*: a retry is allowed when conditions change (new evidence mints a new
   opportunity id — already true) or the operator asks.
3. **Push a compact summary, don't pull the whole history.** Inject a short "recently
   tried / yielded nothing" digest into the context packet
   ([`cli/agent/context.py`](../../cli/agent/context.py)) each turn — not the entire
   failed-action log — so the LLM stops re-picking dead ends without having to call
   `platform_attempts`, and without bloating context.

### B2. False positives — FP-cache matching is substring-based

**Root cause:** [`fp_cache.matches()`](../../backend/src/osprey/services/fp_cache.py#L129)
matches on `title_contains` as a case-insensitive **substring**. This is both too
broad (a short title suppresses unrelated findings on the same target) and too
brittle (reword the title → pattern misses). Exact `observation_signature`
matching is supported but underused.

**Fix:** make the match purely structured — **drop the title-substring path
entirely** (per review: keeping it as a fallback preserves the accidental-
suppression problem). Match only on the exact `observation_signature` and/or a
**normalized finding fingerprint** (finding_type + host + path + param + vuln-class).
A pattern that can't be expressed structurally is not created. This *greatly reduces*
over-suppression — but does **not** eliminate it (per review): two different issues
can still share a too-coarse fingerprint. So the fingerprint is scoped to the actual
claim, every suppression stays visible in the audit trail and reversible, and
suppression is never treated as proof the original was false.

### B3. Fake-looking severity — a brain can file CRITICAL with zero evidence

**Root cause:** `confidence` is computed honestly (no evidence → HYPOTHESIS), but
`claim_severity` is **independent and uncapped**. A checkpoint/agent LLM can
`file_finding(claim_severity=CRITICAL, evidence_records=[])`; it's stored and
surfaced as a CRITICAL claim. AGENTS.md says CRITICAL/HIGH needs observed proof —
but that is **prose, not enforced** at the admission path.

**Fix (twice-revised — a promising unverified lead must still pull the LLM in).**
Keep `claim_severity` and `confidence` **orthogonal and both honest**, and separate
*three* things that an earlier draft collapsed:
- **Presentation:** never surface a bare severity — a finding reads "CRITICAL
  (hypothesis)" vs "CRITICAL (confirmed)". The two are different statements and every
  report/priority/UI surface must say which.
- **Investigation priority — stays driven by the *claim* (per review).** A
  high-potential unverified lead is exactly what should pull LLM/operator attention,
  *to establish whether it's real*. `priority.yaml` already treats a scanner's
  claimed severity as a **priority** signal (not confidence) — keep that; an
  unverified CRITICAL lead ranks high *for investigation*. Using the LLM on leads is
  the goal (design pillar 2), not something to suppress.
- **Confirmed-emergency escalation — gated on *confirmed* severity only.** The
  distinct thing that must require confirmation is "report/alert this as a confirmed
  critical vulnerability." A lead triggers *analysis*; only a confirmed finding
  triggers *"this is real and critical."*
- (This replaces the earlier "refuse/cap CRITICAL" idea, which both conflated claim
  with verification *and* would have stopped the LLM from investigating leads.)

### B4. Close the FP loop automatically

`finding_reverification` already downgrades confidence recency-aware on
RECHECK_FAILED. But FP *learning* is entirely manual/reactive (a human must run
`mark_false_positive`).

**Fix (twice-revised — keep original evidence separate from the latest recheck).**
A timeout/unreachable recheck provides **no new evidence** about whether the
original issue existed, so it must not silently rewrite the confidence. Distinguish
*inconclusive* from *disproved* (today `confidence.py` blanket-downgrades any
`RECHECK_FAILED` to LIKELY — it has no reason subtyping; that is the bug):
- **Inconclusive recheck** (target unreachable/changed/timeout): the finding stays
  **"Confirmed on <date>; latest recheck inconclusive (target unreachable)"** — the
  historical confirmation stands, annotated. No downgrade.
- **Actively not-reproduced** (target up, the specific check now fails): *this*
  legitimately moves the current-state read to LIKELY, with the reason recorded.
- This uses the existing append-only `EvidenceRecord` history (a new
  `RECHECK_FAILED` carries a `reason`) — **no new memory subsystem.**
- A failed/inconclusive recheck **never** creates an FP pattern. Only an explicit
  operator `mark_false_positive` does. Suppression stays visible + reversible via the
  existing suppressed-promotion audit trail.

### B5. Process-lifetime memory & state isolation (verified store-by-store)

Durability audit of every store (so "no memory issues of any kind" is grounded in
what each one actually does, not assumed):

| Store | Backing | Durable across restart? | Risk |
|---|---|---|---|
| `findings_store`, `engagement_graph`, `engagement_store`, `observation_store`, `tool_coverage_store`, `suppressed_promotion_store`, **`scan_run_store`** | Postgres (`SessionLocal`) | **Yes** | — (scan_run_store being durable is what makes the B1 fix sound) |
| `operator_memory` | writes through to the DB-backed graph | Yes | — |
| `fp_cache` | **flat file** `fp_cache/patterns.jsonl` + process-global `_cache` | Yes on one node | **Multi-replica:** file isn't shared → FP learning diverges per worker; `_cache` needs explicit `reload()` to see another process's write |
| `job_store` | **in-memory**, `_MAX_JOBS_KEPT=200` | **No** | The B1 looping bug: failure-cap state lives only here |

Process-lifetime caches (one structure per engagement, each individually bounded,
but the **number of engagement keys is unbounded** — slow RAM growth in a
long-lived shared MCP/backend process):

- `context_delta._STORE` ([context_delta.py:16](../../backend/src/osprey/services/context_delta.py)) — 1 snapshot per engagement, only removed on explicit clear.
- `stdout_index._INDEX` ([stdout_index.py:16](../../backend/src/osprey/services/stdout_index.py)) — 1 bounded deque per engagement, never evicted by count.
- `event_bus._history` ([event_bus.py:31](../../backend/src/osprey/services/event_bus.py)) — same pattern.
- `tool_coverage._CLAIMS` ([tool_coverage_store.py:29](../../backend/src/osprey/services/tool_coverage_store.py)) — reservation locks popped on release; a crash between claim and release leaks the key.
- (`commander_context._CTX_CACHE` is correctly bounded at 64 — the model to copy.)

**Shared-process engagement clobbering (the isolation issue AGENTS.md already
warns about):** the MCP process holds **one** mutable session; a
`platform_set_target` in another chat overwrites it, and the documented mitigation
is "pin `engagement_id=` on every call." That is a convention, not a guarantee —
a single unpinned call writes to the wrong engagement's memory. This is a
*correctness* memory issue, not just hygiene.

**Fixes:**
1. Evict the per-engagement process caches by LRU/TTL (mirror `_CTX_CACHE_MAX`) or
   clear them on engagement unbind — no unbounded key growth.
2. **Isolation follows the *engagement*, not the connection (per review).** One
   connection can carry several engagements, and a background run outlives the
   connection that started it. So resolve the engagement id **at the request
   boundary**, carry that *immutable* identity through every job and every storage
   operation it spawns, and **reject an ambiguous/unbound request** rather than
   falling back to a shared "current" session. A connection-local default alone is
   not isolation. This removes the clobbering class entirely instead of documenting
   around it.
3. **Settled:** deployment is single-node (local-per-user), so `fp_cache` (file) and
   `job_store` (in-memory) stay as-is for v1 — **except** the B1 asymmetry must be
   fixed regardless: failure/empty outcomes read from the durable `scan_run_store`,
   not only the volatile `job_store`. Moving `fp_cache`/`job_store` to Postgres is
   deferred to the teams/SaaS phase. Fixes 1 (per-engagement cache eviction) and 2
   (per-connection isolation) are **both required for v1** — one local backend runs
   several concurrent engagements (dashboard + CLI), so isolation is not SaaS-only.

---

## Part C — The architectural reframe (what to build around)

This is not a code change; it is the lens for Parts B and D and for roadmap
decisions. Stated so it is not re-litigated:

- The **deterministic engine is a procedural decision engine, not a dumb floor.**
  (An earlier draft said "keep it dumb" — that was wrong.) It makes *real decisions
  from observed evidence using explicit procedures*: discover a service → select the
  applicable configured checks → discover parameters → test them → revisit prior
  work when relevant evidence changes. That is genuine non-LLM intelligence (an
  expert system), and it is what runs token-free.
- What the engine does **not** do is *open-ended / creative judgment* — reading an
  ambiguous signal and inventing a novel angle, chaining a bespoke exploit. That is
  the LLM's job, and the only thing it should spend tokens on.
- **"Complete" means covering the applicable configured tests for what was observed,
  and explaining the gaps** — NOT discovering every asset or running every tool on
  every engagement. The engine's output must state what it tested, what produced
  candidates, what failed, and what remains untested (ties to E3).
- The **LLM is the creative/judgment brain**, not the only intelligence: richer
  skills, better context-packet signals, more typed exploitation tools to chain.
- **"Intelligence under the harness"** = substrate quality (a real procedural engine
  + evidence gates + durable anti-loop memory + right-methodology-at-right-time),
  which makes any brain plugged in produce clean, non-looping, evidence-backed work.
- The **moat vs. competitors** is this substrate — specifically the evidence/memory
  layer — not a cleverer rules engine. (Hexstrike = tools-as-MCP, client is the
  brain, no memory. Strix = polished autonomous LLM, thin durable evidence memory.
  Osprey's edge is honest, durable, evidence-graded findings + shared engagement
  memory.)

---

## Part D — Intelligence-source architecture (the "elite harness" target)

Today Osprey's pentesting knowledge lives in **three disconnected representations**:

1. **Prose for the brain** — `skills/*.md` (80 files), with structured frontmatter
   (`name`, `description`, `phases`, `tags`, `mitre`, `requires_tools`),
   authored per [`skills/AUTHORING.md`](../../skills/AUTHORING.md), retrieved by
   [`knowledge_browser.find_skills`](../../backend/src/osprey/services/knowledge_browser.py)
   (simple explainable scoring, no embeddings — correct at this scale), plus
   operator-proposed `skills/learned/` ([`learned_skills.py`](../../backend/src/osprey/services/learned_skills.py)).
2. **Rules for the engine** — `config/*.yaml` (~20 files): `expansion.yaml`
   (recon stage sequencing), `tech_dispatch.yaml` (tech→tool rules, 17 KB),
   `escalation_matrix.yaml` (tool fallback chains), `ingest_rules.yaml`
   (stdout→observation extraction), `priority.yaml` (scoring weights),
   `playbooks.yaml`, `correlation_rules.yaml`, the `*_tools.yaml` tool catalogs, etc.
3. **State/memory** — observations, findings, engagement graph, FP-cache,
   `scan_run_store`, `operator_memory` (preferences/recall).

**The core structural problem:** these three are **not cross-linked.** The skill
`skills/web/*.md` on SQL injection, the `tech_dispatch.yaml` rule that fires
sqlmap, the `escalation_matrix.yaml` fallback chain, and the `priority.yaml`
weight all describe *the same piece of methodology* in four files with no
reference to each other. When the LLM reads the skill it doesn't know which rule
mechanizes it; when the engine fires a rule it doesn't surface the skill; a
methodology change requires editing up to four files and nothing enforces
consistency (this is the same drift that produced the A2 brief contradiction).

### D1. A stable INTERNAL methodology id is the spine; ATT&CK/WSTG are mappings

(Revised per review — do not make ATT&CK the universal identifier.) The primary key
is a stable **internal methodology id** naming a testing unit (e.g.
`web.authz.idor`, `web.auth.session_fixation`). ATT&CK technique ids and
**OWASP WSTG** scenario ids are *optional mappings* hung off it — not the key.
Rationale: for web testing (Osprey's core), WSTG provides concrete test scenarios
(authentication, authorization, session management, input validation) that are the
*right granularity* for a testing unit; a broad ATT&CK label is too coarse to drive
a check. Keep `mitre:` where it adds external interop, add `wstg:` for web, but key
everything on the internal id.

### D2. Start by linking the rules and skills that already exist

(Revised per review — connect existing pieces before building any new knowledge
layer.) Step 1 is the cheap, high-value one: let a `tech_dispatch.yaml` rule and a
`skills/*.md` reference an internal methodology id so the engine can attach *"see
skill web/sqli for how to confirm"* to the opportunity it fires, and a skill can name
the rule that mechanizes it.
- **A skill may reference zero, one, or many methodology ids** (per review), and
  **guidance-only skills are first-class** — not every skill maps to an executable
  rule, and the system must never force a fake rule into existence just to satisfy a
  linkage check.
- The CI drift check therefore fires **only on a *declared* cross-reference that
  dangles** (a rule/skill that names an id or counterpart which doesn't exist), never
  on the *absence* of a reference. Catching drift (the A2 brief contradiction) without
  mandating universal linkage.
Only *after* that basic linkage works, and if it earns its keep, consider a
`methodology_id → {skills, rules, tools, evidence kinds, WSTG/ATT&CK}` coverage map
for the honest coverage report. Do **not** build the elaborate map first.

### D3. Retrieval: keep it explainable, add the missing signals

`find_skills`'s no-embeddings, explainable scoring is the right call at a few
hundred skills — keep it. Improvements:
- rank a **worker's** skills against its *specific* brief+scope (already done for
  spawned workers at [`loop.py:625`](../../cli/agent/loop.py) — generalize the
  pattern so the main loop's context packet does the same for the current asset,
  not just the engagement's top priority);
- surface the skill that matches the **evidence just observed** (tech fingerprint,
  open service), not only the phase — push the relevant skill into context the
  moment its trigger appears, the same push-not-pull principle as B1.

### D4. Learned skills: tighten the promotion path

`skills/learned/` (LLM-proposed, operator-approved, git-ignored for data-leak
safety) is a good design. Make it a real flywheel: `platform_propose_skill`
already requires evidence and is inert until approved. Add (a) a review surface
that shows the proposal next to the evidence that motivated it, and (b) a
periodic consolidation pass (dedupe/merge against shipped skills — the Jaccard
machinery already exists in `learned_skills.py`) so the learned tree doesn't rot.

### D5. Config consolidation

~20 YAML files with overlapping concerns (three `*_tools.yaml` catalogs,
`expansion.yaml` vs `phase_pipeline.yaml`, `playbooks.yaml` vs `tech_dispatch.yaml`).
Audit for genuine overlap and a single documented schema per concern (tool
catalog / stage sequencing / dispatch / scoring). Goal: one obvious place to add
each kind of knowledge, discoverable from `config/README.md`.

---

## Part E — Elite methodology coverage (deterministic completeness audit)

Per the reframe above, the deterministic engine must execute the **full**
battle-tested checklist token-free. Audited against the config that drives it
(`expansion.yaml`, `tech_dispatch.yaml`, `heuristic_engine.py`), here is what is
already covered and where the engine stops short.

### E0. Already covered (token-free in the engine today — do not rebuild)

Sister domains (`domain_hunter`/`crt_sh`), subdomains (passive `subfinder`/`amass`/
`gau`/`waybackurls`/`tlsx` + `gobuster` DNS brute + permutation engine), DNS/email
posture (`dnsx_resolve`/`dnsenum`/`whois`/`email_security_probe`), live/ports/tech/
WAF/CDN (`httpx`/`naabu`/`tech_stack_analyze`/`wafw00f`/`cdn_origin_probe`), service
versioning (`nmap_service_scan -sV`), reverse DNS + ASN (`dnsx_reverse`/`asn_enum`),
**web depth per live host** (`well_known_probe`/`js_recon`/`feroxbuster`/`waybackurls`,
`web_depth: true`), per-tech vuln dispatch (`nuclei`/`wpscan`/`nikto`/`sslyze`/
`graphql_cop`/`arjun`/`sqlmap` on injection points), and OSINT pivots (`theHarvester`/
breach intel/`holehe`/`maigret`/`phoneinfoga`/`exiftool`/`email_permute`). This is a
genuinely broad floor and the starting point, not a rewrite target.

### E1. Coverage gaps (battle-tested steps the engine does NOT auto-run)

| # | Gap | Evidence | Fix | Impact |
|---|---|---|---|---|
| 1 | **No CVE-candidate research from detected service versions.** `searchsploit_lookup` is categorized `exploit` ([`config/exploit_tools.yaml`](../../config/exploit_tools.yaml)), so `NON_AUTONOMOUS_CATEGORIES = {exploit, creds, postex}` ([`heuristic_engine.py:26`](../../backend/src/osprey/services/heuristic_engine.py)) blocks the engine from ever auto-running it. But it is a **read-only local-DB lookup**, not an exploit action. After `nmap -sV` finds a version, nothing surfaces exploit/CVE references for it. | Confirmed not wired | **Recategorize `searchsploit_lookup` as read-only recon/vuln-intel and add a dispatch rule: new SERVICE/version observation → `searchsploit_lookup` (on by default — read-only, safe). The active nmap `vulners` pass is NOT part of this rule — it is the opt-in E1.3 pass (resolves the earlier E1.1-vs-E1.3 contradiction). Both only ever produce *research candidates*, not confirmed CVEs: a version match ≠ vulnerable (patch/backport), so results are candidate leads with applicability still to establish (B0), never confirmed findings.** | **High** |
| 2 | **Sister/associated domains discovered but never worked.** `work_sisters: false` ([`expansion.yaml:102`](../../config/expansion.yaml)) — recorded but not enumerated/probed/port-scanned. | Default off | **(Conservative default — keep off.)** Keep sisters surfaced-for-operator; add a one-flag opt-in (or an authorized-scope allowlist entry) that promotes high-confidence sisters into the worked surface. Do **not** auto-expand scope. | High (opt-in) |
| 3 | **nmap vuln/vulners CVE pass off by default.** `phases.vuln_scan: false` ([`expansion.yaml:93`](../../config/expansion.yaml)). | Default off | **(Keep off by default — intrusive/noisy.)** Make it a one-flag opt-in; pair with searchsploit (E1.1) as the "version → CVE" step for operators who enable it. | Medium (opt-in) |
| 4 | **Subdomain takeover not a routine step.** `subdomain_takeover_check` lives only in `escalation_matrix.yaml` + the catalog, never auto-run on dangling CNAMEs. | Not in expansion/dispatch | Add a dispatch rule: CNAME-to-unresolved / dangling-CNAME observation → `subdomain_takeover_check`. Read-only and in-scope (it only checks the target's own dangling CNAMEs), so **on by default**. Elite always checks. | Medium |
| 5 | **No automatic full-port escalation.** Engine uses `naabu` top-ports; no deterministic escalation to `1-65535` on high-value hosts. | — | **(Opt-in — intrusive/slow.)** Offer full-range sweep as a one-flag option (auto-chunked to a background job); default stays top-ports. Honor an explicit "no full port scan" constraint either way. | Medium (opt-in) |
| 6 | **Shallow crawl.** Default web_depth is `gau`/`wayback`/`feroxbuster`; active crawling (`katana`/`hakrawler`) isn't a routine depth step. | — | Add `katana` (or `hakrawler`) to `web_depth` so every live app is actively crawled, not only history-mined. | Low–Med |
| 7 | **OSINT breadth** — no git/secret search, cloud-bucket enumeration, DNS zone-transfer attempt, or dork step; `shodan_search` only if keyed. | Partial | Add the ones that are deterministic and safe (zone-transfer attempt, bucket-name probing from org/domain, `shodan_search` when keyed) as apex-level OSINT opportunities. | Med |

### E2. The admission principle for "what the engine may auto-run"

Gap E1.1 exposed a mislabeling: the engine's auto-run boundary is
`NON_AUTONOMOUS_CATEGORIES`, but that set is doing two different jobs at once —
(a) "needs explicit user permission because it is intrusive/destructive"
(exploitation, credential attacks, post-exploitation — correct to gate) and
(b) accidentally catching read-only intel tools that happen to live in an
"exploit" catalog file (searchsploit). **Fix the boundary to key on whether an
action is read-only/safe, not which YAML file it was cataloged in.** A read-only
lookup is always engine-eligible; anything that sends an intrusive/stateful
payload stays behind explicit authorization. This makes "the engine does every
safe battle-tested step; the LLM/human owns every intrusive one" structural.

### E3. The no-LLM deliverable

With no LLM configured, the deterministic run must still end by emitting a
**human-actionable dossier** that is honest about coverage (per review — running a
scanner is not proof of coverage). It states, explicitly: **what was tested**, **what
produced candidates** (service→CVE research leads from E1.1, with applicability
still to establish), **what failed** (and why — unreachable/timeout), and **what
remains untested** (applicable checks not yet run, and why). Plus the full asset
graph, the unverified scanner-claims section, and a ranked "what a human should
manually verify next" list drawn from `priority.yaml`.
`report_generator`/`markdown_report` already produce most of this; the gap is making
this coverage-honest dossier the explicit, guaranteed end-state of an engine-only
run, not just something available on request. This is what "something can still be
given to a human to work on" means in practice.

## Part F — Shared runtime + interfaces (CLI and dashboard as peers)

Per the settled decisions and the review: build the **one shared runtime first**
(F2), then connect interfaces. The CLI remains the main harness; the local web
dashboard is a co-equal second client. The existing dashboard
([`dashboard.py`](../../backend/src/osprey/api/v1/endpoints/dashboard.py)) is a
single read-only HTML page over an SSE feed — a good seed, but v1 needs the runtime
work plus three interface pieces. **Order matters: F2 before F1/F3.**

### F1. Control plane (submit + drive from the dashboard)

Add endpoints + UI to **create/bind an engagement and start a run from the
dashboard** (target in → background engagement out), plus pause/resume/cancel. The
backend already has every piece (engagement store, job store, the investigation
drivers, the event bus); this is wiring an HTTP control surface and a form, not new
engine work. The CLI's `HarnessRuntime` is the reference for what to expose.

### F2. One shared headless runtime with a single execution owner — NOT a second loop

(Sharpened per review — this is the critical constraint.) Today the **CLI process**
drives the investigation loop ([`drivers.py`](../../cli/harness/drivers.py)). A
dashboard-driven run needs the loop to survive the browser closing — but the fix is
**not** to build a second orchestration loop in the backend (that would undermine the
CLI-unification the operator asked for). Instead: **extract the one headless runtime**
(the `Runner` already runs server-side in [`agent_runner.py`](../../backend/src/osprey/services/agent_runner.py),
and the deterministic engine is already a backend service) and give **each run exactly
one execution owner**. The CLI and the dashboard are both *clients* of that single
runtime, observing via the event bus — neither owns a private loop. This is careful
runtime-ownership work (who holds the run, how a client attaches/detaches, how
`/resume` reattaches), not "wire a form to a new backend loop." "CLI is the main
harness" stays true: it's one of two clients of one shared runtime.

### F3. Data + graph views

Render the asset graph and attack-path graph (data already in `engagement_graph` /
`platform_visualization` / `platform_attack_path`), the findings table with
evidence grade and the unverified-claims section, the live tool feed (already
streaming), and the ranked manual-verify queue (Part E3). Keep it a thin frontend
over the existing SSE + REST — no business logic in the browser.

**Scope guard for v1:** single operator, local, no auth/RBAC on the dashboard (it
binds to localhost). Note in the teams phase this needs authentication before it is
ever exposed beyond localhost.

## Part G — Operator-extensible deterministic intelligence (design pillar 3)

A pentester must be able to **grow the engine's procedural intelligence themselves,
without writing Python.** The knowledge is already data — this part makes editing it
a supported, safe, first-class workflow rather than an insider skill.

### G1. One documented, validated schema per knowledge file

`config/README.md` names the files but not their contracts. Give each a documented
schema (recon stages `expansion.yaml`, checks `tech_dispatch.yaml`, tool catalogs
`*_tools.yaml`, weights `priority.yaml`, ingest `ingest_rules.yaml`) and a
**validator** that runs on load and in CI: a malformed rule fails loudly with the
offending field, never silently no-ops. This is also what makes operator edits safe.

### G2. "Add your own check" as a first-class path

The highest-value operator extension is a new deterministic **check**: a
`tech_dispatch.yaml` rule (match on an observation → run a tool → record a candidate)
plus an optional `skills/*.md` for how to confirm it, linked by methodology id (D2).
Document this as *the* way to extend the engine, with a worked example (e.g. "detect
technology X → run check Y"). A check added this way must flow into `list_step`
opportunities with no code change — the engine is already data-driven
([`expansion.yaml`](../../config/expansion.yaml) is "the single source of truth"),
so this is mostly documentation + the validator + hot-reload.

### G3. Atomic hot-reload, last-known-good, and per-action methodology version

(Hardened per review.) Edits reload without a restart (several files already have
`reload_*()`/`lru_cache` clears — make it uniform and operator-triggerable), but:
- **validate the whole new config atomically** — it applies all-or-nothing; a
  malformed edit is rejected with the offending field named and the **last working
  configuration is retained**, never half-applied (this is part of the "no flaky
  state" guarantee — a bad edit must not leave the engine in an in-between state);
- **record which methodology version each action used**, so an engagement run is
  reproducible against the config that actually drove it and the report can say "run
  under methodology vN";
- an operator-authored rule/skill is tagged with its origin (local vs shipped) for the
  report and the drift check, and the learned-skills tree
  ([`skills/learned/`](../../skills/learned)) remains the LLM-proposed, operator-
  approved channel for the same extension surface.

This pillar also serves design pillar 2: a richer deterministic floor plus more
linked skills is exactly what the LLM draws on — operator extensions become LLM
leverage automatically.

## Suggested sequencing

Reordered to the review's recommendation: **fix correctness before adding
capability.**

1. **Part B0** (evidence confirmation = entailment + human-provenance for CONFIRMED)
   — the fake-confirm hole; the single most important fix. ~2–3 days.
2. **Part B5 fix 2** (engagement-scoped immutable isolation threaded through jobs/
   storage) — correctness, and a prerequisite for concurrent runs / the dashboard. ~1–2 days.
3. **Part B1** (unify retry decisions on the existing `scan_run_store`; compact
   "already tried" digest into context) — the looping bug. ~1–2 days.
4. **Part A** (dead-code cleanup *after* re-checking callers; scratch-artifact
   gitignore + packaging exclusion — **not** deleting `deliverables/`/study dirs). ~1 day.
5. **Part E1.1 + E2** (service→CVE *candidate research* + read-only/intrusive
   admission boundary) — the battle-tested step the engine currently skips; results
   are candidates, not confirmations (B0). ~1–2 days.
6. **Part D2** (link existing `tech_dispatch` rules ↔ skills by internal methodology
   id + drift CI) — cheap, stops methodology drift. ~1–2 days.
7. **Part E1.4 + safe E1.6/E1.7 + E3** (takeover check, active crawl, safe OSINT, and
   the coverage-honest no-LLM dossier). Staged, benchmark-validated.
8. **Part B3** (severity shown only with confidence; triggers gate on *confirmed*) +
   **B4** (RECHECK_FAILED + reason, no auto-FP) + **B5 fix 1** (cache eviction). ~2 days.
9. **Part B2** (signature/fingerprint FP matching, visible + reversible). ~1–2 days.
10. **Part F** (**F2 shared runtime/single owner FIRST**, then F1 control plane, then
    F3 data+graph views) — CLI + dashboard as peers on one runtime; depends on B5.2 + E3. Stage it.
11. **Part G** (operator-extensibility: schema+validator per knowledge file,
    "add your own check" path, hot-reload + provenance) — pillar 3; lands alongside
    D2 since both touch the rule/skill contract. ~2–3 days, stageable.
12. **Part D1/D3/D4/D5** (methodology-id spine with optional ATT&CK/WSTG; retrieval;
    learned-skill flywheel) — incremental, after the linkage in step 6 earns its keep.

**Rough release cut for v1 (solo, local):** B0 → B5.2 → B1 → A → E1.1/E2 → D2 →
E1.4+E3 → B3/B4 → G1/G2 → F. Opt-in intrusive breadth (sisters/full-port/vulners)
and the coverage-map layer (D1) land after the first tag.

## First milestone — prove ONE vertical slice before broad build-out

This plan has now had enough review. The next step is **not** another revision — it
is to validate the architecture on one real end-to-end path, because that will tell
us whether the design delivers the intended harness far better than more planning.

**Slice 1 (the whole harness in miniature):** pick one real authorized target and
demonstrate, visibly, in order:
1. the engine **discovers an asset** (subdomain/host),
2. **selects an applicable check** from observed evidence (procedural decision — e.g.
   a detected service version → the searchsploit candidate lookup, E1.1),
3. **executes it visibly** and **retains its evidence** (traceable, B0),
4. the **LLM investigates one useful lead** using a ranked, budget-bounded skill
   (pillar 2 / B3), without re-triggering on it unchanged,
5. the run **resumes without re-doing** the already-tried work (B1),
6. it **produces the coverage-honest report** (E3) — tested / candidates / failed /
   untested.

**Slice 2 (extensibility proof):** an operator **adds a second check through the
documented config path** (G2), and it shows up and runs with no core-code change.

Only after both slices work do we broaden coverage (rest of E), the dashboard (F1/F3),
and the knowledge layer (D1/D3/D4). If a slice exposes a design flaw, fix the design
*then* — not by pre-emptively expanding the plan now.

## Non-goals (explicit)

- Do **not** give the deterministic engine *judgment* — no open-ended reasoning,
  no second LLM control plane. It may be made as **complete** as the elite
  checklist (Part E — that is wanted), but it never *decides* in the open-ended
  sense; it executes battle-tested procedure and ranks. Completeness is the goal;
  cleverness is not.
- Do **not** reintroduce any observation→finding auto-promotion (Plan 19 killed it;
  Part B keeps it dead).
- Do **not** add a third opportunity-picking control plane (the deleted
  `LLMOpportunityDriver` anti-pattern, [`drivers.py:530`](../../cli/harness/drivers.py)).
- Do **not** replace the explainable skill scorer with embeddings/ML at current
  scale (D3).

## Verification per part

- **A:** `git grep` shows zero non-test references to each deleted symbol; full
  test suite scoped to `cli/` + `phase_supervisor` passes; clean tree.
- **B1:** restart the backend mid-engagement; an opportunity whose **failure budget
  is already exhausted** (`_MAX_OPPORTUNITY_FAILURES`, read from `scan_run_store`, not
  volatile jobs) is not re-offered — but a *single* prior failure does **not** block a
  retry, and new evidence (new opportunity id) always re-opens it. The context packet
  carries a compact "recently tried / empty" digest, not the full log.
- **B5.2:** two concurrent engagements on one backend never cross-write each other's
  findings/graph even with an unpinned call — because each request's engagement id is
  resolved at the boundary and threaded immutably through its jobs/storage, and an
  ambiguous unbound request is rejected (not: a connection-local default).
- **B2:** a recurrence matching the structured fingerprint/signature of a marked FP is
  suppressed; a *different* issue is not — while acknowledging a too-coarse fingerprint
  can still collide, so suppression stays claim-scoped and reversible (not "overmatching
  is impossible").
- **B0:** a `file_finding` whose only confirming record is an agent-provenance
  attestation, or a REPRODUCTION whose excerpt is real but does not entail the title,
  does **not** reach CONFIRMED. Its confidence is then whatever the *evidence* earns
  (HYPOTHESIS with no corroboration, LIKELY with ≥2 tools) — "does not confirm" is a
  **ceiling**, never an automatic LIKELY. Tests for both the attestation and the
  non-entailing-excerpt case.
- **B3:** no report/priority/checkpoint surface ever shows a bare severity — always
  "(hypothesis)" vs "(confirmed)"; an escalation trigger fires only on *confirmed*
  high/critical, verified by a test with an unverified CRITICAL lead present.
- **B4:** an *inconclusive* recheck (target unreachable/timeout) leaves confidence
  **unchanged** and annotates "confirmed on <date>; latest recheck inconclusive";
  only an *active not-reproduced* recheck (target up, check now fails) downgrades to
  LIKELY. Neither creates an FP pattern — only an explicit operator action does.
- **E1.1/E2:** on an engagement with a versioned service, an engine-only run (no
  LLM) auto-produces CVE candidates for that version; a read-only tool is
  engine-eligible while an intrusive one still requires authorization.
- **E3:** an engine-only run with no LLM ends by emitting the human-actionable
  dossier (asset graph + service/version→CVE + unverified claims + ranked
  manual-verify list) as its guaranteed end-state, not only on request.
- **D2:** every *declared* cross-reference resolves (CI fails on a dangling one);
  a skill with zero or many methodology ids, and a guidance-only skill, are both
  accepted — the check never forces a rule to exist. (D1's coverage map only after.)
- **Determinism guarantee:** a property test feeds the **same recorded evidence set
  (with its timestamps) and same check version** twice — including with the evidence
  *fed* in a different order — and asserts an identical verdict; and it asserts that
  changing a *recorded timestamp* (confirm-before-recheck vs recheck-before-confirm)
  *can* change the verdict. No verdict reads wall-clock. (Live re-scans are explicitly
  out of scope — they may differ.)
- **G (extensibility):** an operator adds a new `tech_dispatch` check (+ optional
  skill) by editing config only; it appears as a `list_step` opportunity after
  hot-reload with no code change and no restart; a malformed edit fails validation
  loudly, naming the field, rather than silently no-op'ing.
