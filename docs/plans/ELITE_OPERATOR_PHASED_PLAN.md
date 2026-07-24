# Elite Operator Phased Plan

**Goal:** Stop treating the LLM as a static tool runner of YAML recipes. Make the platform a **lab + referee + shared notebook** the operator can *write* into.

**Principle:** Thin prompt, fat memory. Config owns safety and defaults. Cognition (tool choice, relation names, parse meaning, hypotheses) belongs to the LLM — platform stores and enforces evidence law.

```
CONFIG (platform)              COGNITION (LLM)
• evidence grades              • which tool next
• ingest regex (bootstrap)     • custom script / parse meaning
• scan_budget / allowlist      • relation names
• finalize hard blocks         • hypothesis → confirm
                               • when to stop / report
              └──── GRAPH / FINDINGS (shared) ────┘
```

**Do not:** grow AGENTS.md, add per-vendor skill packs, or add more mandatory rituals per error.

**Work style:** Complete one phase → verify acceptance criteria → commit → start next phase.

---

## Status legend

| Status | Meaning |
|--------|---------|
| `TODO` | Not started |
| `IN_PROGRESS` | Active |
| `DONE` | Acceptance criteria met |
| `SKIP` | Explicitly deferred |

---

## Phase 0 — Cleanup & baseline (low risk)

**Why first:** Shrink dead surface so later work isn’t built on unused REST. Does not change LLM behavior yet.

### 0.1 Dead tool metadata APIs

OpenCode finding: `get_tool(name)` and `get_tools_by_mcp_server()` are metadata-only; execution never uses them.

| Task | Files (approx) | Action |
|------|----------------|--------|
| Remove or deprecate `GET /api/v1/tools/{name}` | `api/v1/endpoints/tools.py` | Drop if no external UI depends on it |
| Remove or deprecate `GET /api/v1/tools/by-server/{server}` | same | Drop |
| Keep `list_tools` / `get_tool_catalog` | `tool_registry.py` | Merge summary into `list_tools(summary=True)` if duplicated |

**Acceptance**

- [ ] Typed tools + `platform_exec` still hit `POST /api/v1/mcp/execute`
- [ ] `platform_tools` still lists catalog
- [ ] No internal caller references removed endpoints

### 0.2 Dead engagement HTTP routes

Services stay; unused public routes go.

| Endpoint | Service still used? | Action |
|----------|---------------------|--------|
| `GET /{id}` | Possibly CLI — verify | Keep if CLI uses; else drop |
| `GET /{id}/tree` | Yes — `commander_context` | Drop HTTP route only |
| `GET /{id}/network-surface` | Yes — context / open_loops | Drop HTTP route only |
| `GET /{id}/tool-coverage` | Yes — open_loops | Drop HTTP route only |
| `DELETE /{id}` | No MCP consumer | Drop or gate behind admin |

**Keep (MCP/CLI used):** analyze-target, list, create, resolve, runs/ensure, enumerate-pending-sisters, fanout-assets.

**Acceptance**

- [ ] `platform_context`, open loops, fanout still work
- [ ] Grep shows no MCP/`server.py` calls to deleted routes

### 0.3 Hygiene (optional same PR)

- [ ] Ensure `.env` not tracked; `.gitignore` covers `__pycache__`, reports
- [ ] Fix `domain-hunter` submodule (`160000`) → normal files if needed
- [ ] Do **not** expand AGENTS.md

**Phase 0 exit:** Cleaner API map; behavior unchanged for OpenCode agent.

---

## Phase 1 — Cognition write APIs (highest ROI)

**Status:** `DONE` (implemented)

**Why:** Fixes “I cannot name relations / teach scoring / invent graph shape.” Makes the LLM an author of memory, not only a reader of config.

### 1.1 `platform_graph_link`

MCP + backend endpoint to create edges the operator names.

```text
platform_graph_link(
  source="host:erp.example.com",
  target="host:ess.example.com",
  relation="shares_auth_cookie",   # free string (sanitized)
  evidence_grade="inferred",       # observed | inferred | unverified
  evidence="same Set-Cookie domain + shared chunk hash",
)
```

| Task | Detail |
|------|--------|
| API | `POST /api/v1/hybrid/graph/link` |
| Persist | `EngagementGraph.operator_link` + observation finding |
| Grades | Non-observed → `hypothesis_<rel>` edge (max 64 chars) |
| Query | `platform_graph_query` returns `hypothesis: true/false` on edges |
| Finalize | Hypothesis edges are not observed proof |

**Files:** `operator_memory.py`, `engagement_graph.py`, `hybrid.py`, `platform-mcp/server.py`, `test_operator_memory_phase1.py`

**Acceptance**

- [x] Operator can create `same_app_as` / `likely_origin_of` without editing YAML
- [x] Edge appears in `platform_graph_query`
- [x] Finalize still blocks weak CRITICAL without observed proof (unchanged path)

### 1.2 Hypothesis edges (first-class)

| Task | Detail |
|------|--------|
| Convention | `hypothesis_<name>` when grade ≠ observed |
| Display | Graph query labels `hypothesis: true` |
| Promotion | Re-link with `evidence_grade=observed` for asserted name |

**Acceptance**

- [x] Hypothesis edges visible and filterable
- [x] Not treated as observed proof in finalize (edges ≠ severity claims)

### 1.3 `platform_tag_asset`

Runtime crown-jewel override without editing `thinking_model.yaml`.

```text
platform_tag_asset(
  asset="erp.example.com",
  role="business_portal",
  boost=25,
  reason="PMIS title + /api JSON observed",
)
```

| Task | Detail |
|------|--------|
| Store | Finding tagged `operator_tag` + node metadata |
| Score | `crown_jewels.py` adds boost + `tag:<role>` reason |
| API | `POST /api/v1/hybrid/tag-asset` / MCP `platform_tag_asset` |

**Acceptance**

- [x] Tag changes ranking without config deploy
- [x] Tags persist across tools in same engagement

### 1.4 Durable think → memory

| Option A (chosen) | Option B |
|----------|----------|
| `platform_think` → `POST /api/v1/hybrid/think` → observation finding | — |

**Acceptance**

- [x] Prior hypotheses appear in later findings
- [x] AGENTS still says think is optional

### 1.5 Script markers v2

```text
FINDING|observed|high|url|Title|evidence…
PATH /x 401
REL|host:a|same_app_as|host:b|shared JS hash
REL|inferred|host:a|likely_origin_of|ip:1.2.3.4|evidence
HYPOTHESIS|erp backend|needs REST walk
```

**Acceptance**

- [x] Script stdout creates findings **and** optional edges via REL|
- [x] Custom probes feed graph without catalog parsers

**Phase 1 exit:** LLM can write relations, tags, hypotheses into memory. Graph is no longer write-only by platform.

---

## Phase 2 — Quiet suggestions (stop training the autopilot)

**Why:** Loud `TRY NEXT` / `FALLBACK` / `try: nmap` trains a static runner. Keep **data**; drop **orders**.

### 2.1 Open loops = gaps, not commands

**Before**

```text
[ips_unscanned] 16 IPs → try: nmap_syn_scan
```

**After**

```text
[ips_unscanned] 16 IPs with hostnames, zero port evidence
  gap: port discovery needed
  hints: [optional short list, not mandatory]
```

| Task | Files |
|------|-------|
| Reshape `build_open_loops` | `open_loops.py` |
| Context formatter | `commander_context.py`, `server.py` |
| AGENTS one-line tweak | Prefer “close a gap” over “follow try:” |

**Acceptance**

- [x] Loops never require a single tool name
- [x] Agent can close gap via script/job/fanout without fighting the prompt

### 2.2 Soften post-exec prescription

In `_format_exec_result` (`server.py`):

| Keep | Soften / move |
|------|----------------|
| success, stdout summary, finding titles | Soften `TRY NEXT` → “gap note if any” |
| OPEN LOOPS as gaps | Drop or demote `FALLBACK TOOLS` to optional |
| Artifact paths | Shorter footer (no stage language) |

**Acceptance**

- [x] Tool cards shorter; less imperative language
- [x] Failures still show useful error + allowlisted alternatives only when needed

### 2.3 Dispatch / escalation = signals

| Task | Detail |
|------|--------|
| `tech_dispatch` | Emit `signals_met: [...]` advisory, not “run waybackurls” |
| `escalation_matrix` | Keep for recovery_bridge internals; don’t dump full chains into every MCP response |

**Acceptance**

- [x] Context shows signals/gaps, not forced chains
- [x] Recovery still works when tools fail

### 2.4 Context budget hard limit

Target per `platform_context` turn (~80 lines equivalent):

1. Session + target  
2. Crown jewels top 5  
3. Open gaps (3–5)  
4. Jobs status (n/4)  
5. Delta / new since last call  
6. Optional one signal card  

**Pull on demand:** `platform_tools(query=)`, `platform_skills(path=)`, `platform_playbook(name=)`, `platform_findings`.

**Acceptance**

- [x] No full catalog / full skill dump in default context
- [x] Agent can still fetch details when stuck

**Phase 2 exit:** DONE — Platform advises with evidence; LLM chooses tools. Autopilot pressure reduced.

---

## Phase 3 — See more (ingest + correlation)

**Why:** 7 regex rules are too blind. Expand bootstrap ingest; add lightweight cross-finding correlation — without replacing LLM authorship from Phase 1.

### 3.1 Expand ingest rules (~15–20 patterns)

Add (examples — tune in `ingest_rules.yaml`):

- HTTP status + title lines  
- TLS SAN / CN hints  
- Redirect chain markers  
- Auth challenge (`WWW-Authenticate`)  
- Version banners  
- JSON API key shapes (keep SPA catch-all demotion)  
- JS route-ish path hints (conservative)

**Rule:** New patterns in YAML only. **No** new AGENTS bullets per pattern.

**Acceptance**

- [x] More useful findings from httpx/nmap/script stdout without manual record  
- [x] SPA false-API still demoted  

### 3.2 Cross-finding correlator

After ingest batch:

| Signal | Hypothesis edge / tag |
|--------|------------------------|
| Same IP + similar titles | `likely_same_app` |
| Same cookie domain / issuer | `shares_auth` (hypothesis) |
| Host + many URL children | boost app-depth gap |

**Acceptance**

- [x] Correlations appear as **hypothesis**, not observed CRITICAL  
- [x] Operator can confirm/override via graph_link / tag_asset  

### 3.3 Raw stdout index (lightweight)

- Store last N tool artifact paths / snippets queryable from context or findings  
- Avoid dumping full 200k stdout into every card (already partially truncated)

**Acceptance**

- [x] Unparsed nuance not lost forever  
- [x] Context stays small  

### 3.4 JS / API extract as script convention (not new agent)

Document + optional smoke script pattern:

- Download main.*.js → extract `/api`, `/rest`, routes  
- Print `FINDING|` + `REL|` / `PATH`  

Optional later: one typed helper that wraps a fixed script template (still LLM-triggered).

**Acceptance**

- [x] SPA/API depth possible without new mega-skill  
- [x] Results land in graph via Phase 1 markers  

**Phase 3 exit:** DONE — Platform sees more automatically; LLM still owns hard cases via script + write APIs.

---

## Phase 4 — Speed (parallelism & jobs)

**Why:** Elite = time-to-useful-surface, not checklist length.

### 4.1 Job visibility everywhere

- Every `platform_context` header: `jobs: 2/4 running [amass, nmap]`  
- After slow tools: soft hint “consider job_start for parallel branch”

### 4.2 Fanout after list discoveries

- After large subdomain/host lists: gap `batch_probe_pending` (not “must fanout”)  
- Keep max concurrent jobs = 4 (or make configurable)

### 4.3 Auto-suggest jobs for known-long tools

When tool in `{amass, rustscan, nmap_*, bulk httpx}` and timeout ≥ 120s:

- Prefer documenting job path in tool docstring / soft hint  
- Do **not** auto-start without LLM/operator intent (avoid surprise)

### 4.4 Chunked scan helper

- Script template or skill snippet: scan IP list in chunks of N  
- Ties to scan_budget (never widen to 1-65535 without confirm)

**Acceptance**

- [x] Agent routinely runs parallel branches on real targets  
- [x] Fewer “I went linear” failures  

**Phase 4 exit:** DONE — Parallel use is natural; long work doesn’t freeze the chat.
Config: `config/parallelism.yaml` owns caps + long-tool names. Soft notes only — **never auto-start**.

---

## Phase 5 — Proof & report trust

**Why:** Elite output is trusted. Noise and hype kill trust.

### 5.1 Evidence chains

- Findings may reference `derived_from: [finding_ids]`  
- Correlator / graph_link can set parents  

### 5.2 Finalize v2

Block COMPLETE when:

- Weak CRITICAL / CVE without observed + evidence snippet  
- SPA false API claims  
- Attack path is **hypothesis-only** with no observed HIGH (configurable)  
- Keep waive for infra noise when strong observed proof exists  

### 5.3 Report sections

1. Observed (proof)  
2. Inferred  
3. Hypotheses / open loops  
4. Crown jewels + operator tags  

### 5.4 Operator mirror trim

- Tool card: status + top findings + gaps  
- Full stdout: artifact path  

**Acceptance**

- [x] Operator trusts COMPLETE reports  
- [x] Chat not flooded with raw dumps  

**Phase 5 exit:** DONE — Proof hygiene matches elite operator standards.
Config: `config/finalize_rules.yaml`. Report via `platform_report_outline`. Exec cards trimmed.

---

## Phase 6 — Hardening & dry-run

**Motto:** help the LLM stay elite and **wide** — hygiene and soft instincts, not new cages.

### 6.1 Tests

- Graph link + hypothesis edges  
- Tag asset scoring  
- Open loops gap shape  
- Script REL/HYPOTHESIS markers  
- Finalize blocks (soft by default)

**Acceptance**

- [x] Elite phase suite green (`test_*_phase*.py` + `test_elite_smoke_phase6.py`)

### 6.2 Repo hygiene

- [x] domain-hunter as files (not submodule)  
- [x] Ignore reports / pyc (already in `.gitignore`)  
- [x] YAML source of truth (`config/README.md`; stale ingest JSON stubbed)

### 6.3 Real engagement dry-run

Soft skill only — **not** enforced: `skills/shared/engagement-dry-run.md`

Operator instincts (reorder/skip freely):

- Sisters + multi-enum when inventory is thin  
- Parallel jobs when work is slow  
- Custom script → FINDING + REL when inventing  
- graph_link / tag_asset when you author the story  
- Finalize + report_outline for honest COMPLETE vs PARTIAL  

**Phase 6 exit:** DONE — Ship-ready; platform stays a lab + referee, not a narrow playbook.

---

## Phase 7 — Queryable memory (elite stretch)

**Motto:** fat memory the LLM can search — no new playbooks, no skip-orders.

| Capability | Tool / API |
|------------|------------|
| Free-text flashlight | `platform_memory_search` → `/hybrid/memory-search` |
| Evidence parents/children | `platform_evidence_chain` → `/hybrid/evidence-chain` |
| Attempt history (advisory) | `platform_attempts` → `/hybrid/attempts` |
| Phase 0 polish | Legacy tool routes `deprecated=True`; `docs/PHASE0_DEAD_ROUTES.md` |

**Acceptance**

- [x] Operator can find a fact without dumping all findings  
- [x] `derived_from` chains are walkable  
- [x] Attempt history never forbids a re-run  
- [x] No AGENTS ritual growth beyond a one-line tools table  

**Phase 7 exit:** DONE — Best-in-class operator lab: writable + searchable memory.

---

## Explicit non-goals (do not do in these phases)

| Non-goal | Why |
|----------|-----|
| Grow AGENTS.md with per-error rules | Burns context; trains checklist bot |
| Per-vendor skill packs | Same |
| Fake “AI decision engine” with static tool scores | HexStrike trap |
| Shannon Temporal / multi-agent rewrite | Premature until Phase 1–2 done |
| Auto-executing playbooks | Kills free will |
| Deleting evidence grades / scan_budget / finalize | Those are the referee — keep |

---

## Suggested schedule

| Phase | Focus | Rough effort |
|-------|--------|--------------|
| **0** | Dead API cleanup | 0.5–1 day |
| **1** | graph_link, tag_asset, markers, durable think | 3–5 days |
| **2** | Quiet loops / context / hints | 2–3 days |
| **3** | Ingest + correlator | 3–5 days |
| **4** | Jobs / fanout UX | 2–3 days |
| **5** | Finalize / report / trim | 2–3 days |
| **6** | Tests + dry-run | 2–3 days |

**Order is intentional:** Phase 1 before Phase 3 (write APIs before more regex). Phase 2 early enough that new features don’t reintroduce loud prescriptions.

---

## Phase checklist (copy per PR)

```text
Phase: _
Branch: _
Done:
- [ ] Implementation
- [ ] Acceptance criteria checked
- [ ] No AGENTS.md bloat
- [ ] Smoke: platform_health + one tool + context
- [ ] Commit message focuses on why
```

---

## Success definition (end state)

The agent is elite when:

1. It **decides** next probes from evidence (platform only surfaces gaps).  
2. It **writes** custom relations and tags into the engagement graph.  
3. Custom scripts **update memory** as well as catalog tools.  
4. Long work runs in **jobs**; surface expands in parallel.  
5. Reports are **proof-gated**, not hype.  
6. Prompts stay **thin**; memory stays **fat**.

---

## Related docs

- `docs/PLATFORM_IMPROVEMENT_PLAN.md` — earlier improvement notes  
- `docs/PHASE_A_ATTACK_SURFACE_SPINE.md` — surface expansion instincts  
- `opencode_analysis.txt` — OpenCode gap analysis (input to this plan)  
- `AGENTS.md` — keep short; do not turn this plan into AGENTS content  

---

## Next action

Phases **1–7** are implemented (0 documented as optional dead-route polish).

**Phase 7 — Queryable memory (elite stretch):**
- `platform_memory_search` — free-text flashlight over findings/graph/attempts
- `platform_evidence_chain` — walk `derived_from` parents/children
- `platform_attempts` — advisory try-history (never a ban)
- Phase 0: legacy tool routes marked deprecated; see `docs/PHASE0_DEAD_ROUTES.md`

Operate with thin prompts + fat, searchable memory.

