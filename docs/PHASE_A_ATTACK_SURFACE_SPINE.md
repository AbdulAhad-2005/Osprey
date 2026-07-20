# Phase A: Attack-Surface Spine — Implementation Plan

> **Goal:** Make one recon→network path work end-to-end with durable memory and honest
> per-asset coverage gaps — before adding vuln/exploit phases or more tools.
>
> **Principle:** Commander (OpenCode) decides *what* to run; the backend remembers
> *what's done* and *what's left*.

**Work tree:** `llmwork/AI-Pentesting-Tool`

---

## 1. How it works today

### Runtime flow (OpenCode path)

```
OpenCode (Commander)
  → platform-mcp (3 tools: health / context / exec)
  → FastAPI backend
       → tool_execution (governance, command_builder, docker exec → Kali)
       → summary_agent.summarize_execution (parser → Finding objects)
       → findings_store (RAM list) + engagement_graph (RAM nodes/edges)
       → commander_context (gaps, pivots, catalog, skills)
  → OpenCode reads context, picks next tool manually
```

### What exists and works

| Layer | Status |
|--------|--------|
| Tool execution kernel | Works — validate, build command, run in Kali, parse stdout |
| ~14 active recon/network tools | subfinder, httpx, nmap, domain_hunter, etc. |
| Parsers | subfinder, httpx, nmap, domain_hunter → structured `Finding` |
| 3-tool MCP for OpenCode | Slim interface, auto `run_id` |
| Skills / pipeline docs | 8-stage methodology in `AGENTS.md` + `skills/pipeline/` |
| Engagement API | Create/list engagements — **in-memory only** |
| Graph (basic) | Nodes: subdomain/host/url/ip/port; edges: `resolves_to`, `hosted_on` |
| Coverage reflection | Phase-level only (“Subdomain enumeration” missing if zero SUBDOMAIN findings) |
| Multi-agent backend | Commander + PhaseAgent + Orchestrator (for `/api/v1/agent/chat`, not OpenCode's main path) |
| Postgres + SQLAlchemy session | Wired in `db/session.py` — **not used for findings/graph** |
| Workflows | `config/workflows.yaml` + `workflow_runner.py` — 4 fixed workflows, optional API |

### What breaks in practice (zong.com.pk run)

1. **No durable memory** — restart backend → all findings/graph gone
2. **Engagement often empty** — `PENTEST_ENGAGEMENT_ID` unset → findings not tied to a real engagement
3. **Coverage is phase-level, not asset-level** — “Port scan missing” even when 300/340 hosts scanned
4. **Sister → subfinder doesn't chain** — 27 sisters found; backend never says “run subfinder on sister X”
5. **No attack-surface tree** — LLM must rebuild domain→sisters→subs→IPs→ports by hand
6. **IP pivot underused** — shared infra / CF / origin not first-class graph signals
7. **OpenCode tracks progress in chat** — exactly what the backend should own

---

## 2. Target architecture (after Phase A)

```
platform_exec(tool)
  → parse → persist Finding + AssetNode + AssetEdge (Postgres)
  → recompute coverage_gaps (per asset, not per phase)
  → update engagement progress

platform_context(phase)
  → findings summary (from DB)
  → graph summary + attack_surface_tree (from DB)
  → coverage_gaps[]  ← actionable, asset-scoped
  → active_pivots[]  ← derived from graph, not dumb heuristics
  → tool catalog + skills (unchanged)
```

### Explicitly NOT building in Phase A

- Full autopilot pipeline that runs all 8 stages without LLM approval
- Silent auto-chain after `domain_hunter` (no subfinder fan-out without Commander decision)
- Nuclei, sqlmap, KittySploit, or 50 more tools
- Bulk DarkMoon/Shannon skill file imports

### Optional later

`POST /api/v1/engagements/{id}/fan-out/pending-sisters` — explicit helper when Commander asks.

---

## 3. Milestones (build order)

### Milestone 0: Engagement identity (1–2 days) ✅ DONE

**Problem:** Findings float with empty `engagement_id`; MCP session doesn't create/link engagements.

**Do:**

- On first `platform_context` or `platform_exec` without `engagement_id`:
  - Auto-create engagement from seed domain (`PENTEST_TARGET` env or first tool `domain` param)
  - Return `engagement_id` in MCP output every time
- MCP: if `PENTEST_ENGAGEMENT_ID` unset, call `POST /api/v1/engagements/` once, cache ID for process lifetime
- Persist engagements in Postgres (replace in-memory `engagement_store`)

**Files:**

- `models/engagement.py` (new)
- `models/run.py` (new — table ready for M1)
- `services/engagement_store.py` → DB repo
- `platform-mcp/server.py`
- `api/v1/endpoints/engagements.py` (unchanged API)
- `alembic/versions/001_engagements_runs.py`
- `db/migrate.py` + `main.py` lifespan

**Acceptance:** Two `platform_context` calls in same session show growing findings; engagement ID stable and visible.

---

### Milestone 1: Postgres persistence (3–5 days) — highest leverage ✅ DONE

**Problem:** `findings_store` + `engagement_graph` are RAM-only.

**Models** (`backend/src/pentest_platform/models/`):

| Table | Purpose |
|--------|---------|
| `engagements` | id, target, name, status, roe JSON, created_at |
| `runs` | id, engagement_id, started_at |
| `findings` | All `Finding` fields + engagement_id, run_id, indexes on type/source |
| `asset_nodes` | **composite PK (engagement_id, id)** — same label on two targets never collide |
| `asset_edges` | source_id, target_id, relationship, engagement_id (+ unique per engagement) |

**Do:**

- Alembic migration `002_findings_graph`
- Refactor `FindingsStore` → Postgres (strict `engagement_id` filter)
- Refactor `EngagementGraph` → Postgres on `ingest_finding` / `ingest_many`
- Record `runs` on tool exec; bump `tools_executed` / `findings_count` per engagement
- `summarize_execution` call site unchanged — stores become durable

**Acceptance:** `docker restart backend` → prior findings still in `/api/v1/findings/` and graph summary.
**Multi-target:** two engagements with the same subdomain label keep separate nodes/edges/findings.

---

### Milestone 2: Asset-scoped coverage gaps (3–4 days) ✅ DONE (soft / advisory)

**Problem:** `phase_reflection.py` only checks “any SUBDOMAIN finding exists?” — useless at 340 hosts.

**New:** `services/coverage_engine.py` + `schemas/coverage.py`

Gaps are **advisory** (`advisory=true`, confidence 0.3–0.7). They never force fan-out.
Unstructured/incomplete parses lower confidence and keep phase-level hints soft.

**Also in M2:** flexible finding storage — `tags`, `extra`, `raw_data`, `notes` (+ `metadata` accepts Any).

| Gap type | Rule (best-effort) |
|----------|------|
| `sister_unenumerated` | domain_hunter / sister-tagged HOST with no SUBDOMAIN under it |
| `root_unenumerated` | Seed domain has no subdomain evidence |
| `host_unresolved` | HOST/SUBDOMAIN with no `resolves_to` edge |
| `ip_unscanned` | IP with no port evidence |
| `ip_ports_no_service_scan` | PORTs exist, no SERVICE findings (one soft gap) |
| `host_cf_no_origin` | CF signal without origin_ip |
| `shared_infra_unprobed` | Shared IP, some siblings not live-probed |
| `phase_missing` | Coarse Shannon check — low confidence only |

**Wire:** `build_commander_context` + `GET /api/v1/hybrid/coverage/{phase}?engagement_id=`

**Acceptance:** After domain_hunter, context lists sister gaps with soft confidence; Commander may ignore.

---

### Milestone 3: Attack-surface tree export (2–3 days) ✅ DONE

**New endpoint:** `GET /api/v1/engagements/{id}/tree?condensed=false`

```json
{
  "seed": "zong.com.pk",
  "seed_branch": { "domain": "…", "subdomains": [ { "host", "ips", "ports", "services", "cf" } ] },
  "sisters": [ { "domain", "role": "sister", "subdomains": […], "incomplete": true } ],
  "orphans": […],
  "stats": { "sisters", "subdomains", "unique_ips", "open_ports", "orphan_hosts" },
  "advisory": true
}
```

- Built from graph + findings — no new storage
- Soft: incomplete branches marked; orphans kept when linkage is unclear
- Condensed text always on `platform_context`; full structured tree when `phase=full`

**Acceptance:** Tree reconstructs seed→sisters→hosts without LLM memory.

---

### Milestone 4: Graph ingest improvements (2–3 days) ✅ DONE

1. **Sister lineage** — `domain_hunter` HOST → edge `seed → sister` (`affiliated_with`)
2. **Shared infra** — second hostname on same IP → `co_hosts` edges + pivot hint
3. **CF/WAF flag** — httpx parser sets `metadata.is_cloudflare` + tag → soft origin-hunt gap
4. **Tool coverage per asset** — soft `tool_coverage` table (`subfinder_scan@domain`) — **never blocks** re-runs; only lowers gap confidence

**Acceptance:** shared-IP hosts get `co_hosts`; CF hosts appear in soft gaps; tool coverage is advisory.

---

### Milestone 5: Network sub-step granularity (2 days) ✅ DONE

Per unique IP (`GET /engagements/{id}/network-surface`):

- `ports_known` — any PORT evidence linked to that IP
- `services_known` — any SERVICE evidence on that IP

Gaps (advisory):

- `ip_unscanned` → `nmap_syn_scan` + alternatives `rustscan_fast_scan` / `masscan_high_speed`
- `ip_ports_no_service_scan` → `nmap_service_scan` with discovered `ports` param

Replaced dumb pivot “subdomains found but no port scan” with per-IP counts when IPs exist.

---

### Milestone 6: Optional fan-out helper (1–2 days, explicit only) ✅ DONE

`POST /api/v1/engagements/{id}/actions/enumerate-pending-sisters`

- Reads gaps where `gap_id == sister_unenumerated`
- Runs `subfinder_scan` **sequentially** only when `dry_run=false` **and** `confirm=true`
- Default body is **dry_run preview** — never silent
- Returns batch summary — does **not** auto-run httpx/nmap
- Skips domains with soft `tool_coverage` marks when `skip_already_marked=true`

Optional MCP tool: `platform_fanout(action="enumerate_sisters")` — same confirm/dry_run rules.

**Do not:** silent auto-chain inside `domain_hunter` completion. (unchanged)

---

### Milestone 7: Skills trim + doc sync (1 day) ✅ DONE

- Kept `skills/pipeline/full-attack-surface-pipeline.md` as **methodology** (not autopilot)
- Updated AGENTS.md + commander skills: read soft `coverage_gaps` from context; tree/network surface over chat memory
- Removed “must complete all 8 / never skip” wording that fought the backend
- Documented optional `platform_fanout` (explicit confirm only)
- Did **not** bulk-import DarkMoon/Shannon skill trees

---

## 4. What to remove or demote (overhead cleanup)

### Remove or stop maintaining

| Item | Why |
|------|-----|
| In-memory-only `FindingsStore` / `EngagementGraph` | Replaced by Postgres repos |
| In-memory `EngagementStore` | Replaced by DB |
| `recovery_bridge.py` HexStrike path in hot exec | Dormant; docker-exec never uses MCP recovery. Keep `escalation_registry` only |
| `use_recovery=true` default on MCP exec | Dead weight; set false or remove from hot path |
| 76 unused tools in OpenCode catalog | Split registry: `ACTIVE_TOOLS` (~15) vs `CATALOG_FULL`. Context shows active only |
| Duplicate gap sources | One source: `coverage_engine` — not phase_reflection + skills + AGENTS.md |
| Workflows in OpenCode docs | Workflows stay as optional backend shortcuts — not primary MCP path |

### Consolidate (keep, narrow scope)

| Item | Action |
|------|--------|
| `workflow_runner.py` + `workflows.yaml` | Optional shortcuts for `/agent/chat` backend loop |
| `phase_reflection.py` | Phase coverage **score** only; gaps → `coverage_engine` |
| `tech_dispatch.py` + `escalation_registry.py` | Keep for tool failure hints |
| `orchestrator.py` + `commander_agent.py` | Keep; share DB stores + coverage_engine with OpenCode path |
| `agent_assist.py` | Keep — thin wrapper to platform kernel |

### Do not add in Phase A

- Nuclei, sqlmap, KittySploit MCP
- 50 more tools
- Full 8-stage autopilot
- DarkMoon/Shannon skill dumps
- Second MCP server
- Postgres for raw stdout (findings + graph only)

---

## 5. File change map

| Action | Files |
|--------|--------|
| **Create** | `models/engagement.py`, `finding.py`, `asset_node.py`, `asset_edge.py`, `asset_coverage.py` |
| **Create** | `services/coverage_engine.py`, `services/graph_tree.py` |
| **Create** | `repositories/findings_repo.py`, `graph_repo.py` (or inline in stores) |
| **Create** | `alembic/` migrations |
| **Modify** | `findings_store.py`, `engagement_graph.py`, `engagement_store.py` → DB-backed |
| **Modify** | `commander_context.py`, `schemas/hybrid.py` → structured gaps + tree snippet |
| **Modify** | `parsers/recon_network.py` → CF metadata, IP from httpx |
| **Modify** | `platform-mcp/server.py` → auto engagement, show gaps + engagement_id |
| **Modify** | `AGENTS.md`, `skills/pipeline/full-attack-surface-pipeline.md` |
| **Demote** | `tool_registry.py` / context builder → active vs full catalog |
| **Optional remove** | `recovery_bridge.py` from exec path if unused |

---

## 6. Phase B (after Phase A passes acceptance)

Only start when zong (or similar) completes without manual tracking:

1. **Web vuln** — nuclei on live HTTP hosts from tree
2. **CVE track** — SERVICE findings → template/CVE lookup
3. **Exploit** — KittySploit as **separate MCP**, not inside backend
4. **OWASP track** — dalfox/nikto scoped to web ports

---

## 7. Acceptance test (definition of done)

Run on `zong.com.pk` via OpenCode:

1. `platform_health` → OK
2. Auto `engagement_id` created and shown on every MCP response
3. `domain_hunter` → sisters in DB + tree + per-sister gaps
4. Commander runs `subfinder` on seed + sisters → gaps shrink
5. `httpx` on subdomain batch → IPs in graph, CF flagged where applicable
6. `nmap` on unique IPs → ports + services in tree
7. `docker restart backend` → steps 3–6 data still present
8. `GET .../tree` returns complete JSON without LLM reconstruction
9. No false gap “port scan missing” when IPs already scanned

---

## 8. Timeline

| Week | Focus |
|------|--------|
| 1 | M0 engagement identity + M1 Postgres models/migration + wire findings |
| 2 | M1 graph persistence + M2 coverage_engine (sister + IP gaps) |
| 3 | M3 tree export + M4 graph ingest (shared infra, CF) + M5 network granularity |
| 4 | M6 optional fan-out, M7 docs, zong acceptance test, overhead cleanup |

---

## 9. First PR (start here)

**Alembic + Engagement/Finding/AssetNode/AssetEdge models + DB-backed `findings_store` + auto engagement in `platform-mcp`.**

Everything else in this plan builds on durable engagement identity and persistence.

---

## 10. Pentesting flow this spine implements

```
Domain (seed)
  → sister domains (domain_hunter)
  → subdomains per seed + each sister (subfinder/amass)
  → live hosts + tech (httpx)
  → hostname → IP resolution
  → IP as pivot (shared infra, CF/origin gaps)
  → port scan (unique IPs)
  → service/version (-sV on open ports)
  → attack-surface tree (JSON export)
```

Vuln checking (CVE + OWASP) and exploit chains are **Phase B** — after this spine is proven.
