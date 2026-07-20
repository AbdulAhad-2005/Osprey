# Pentest Platform — Operator Guide (Current Architecture)

This guide describes the **repollished** platform as it works today: how pieces connect, how tools are listed and run, how memory/graph/findings work, how skills assist the LLM, and where flexibility lives.

Root: `llmwork/AI-Pentesting-Tool/`

---

## 1. Big picture

The platform is an **AI-assisted pentest lab**, not a fixed stage machine.

- **You / OpenCode** = the operator brain (strategy, judgment, invention).
- **Platform** = memory, Kali tools, evidence grades, finalize gate, advisory hints.
- **HexStrike-style ideas we kept**: typed tool schemas, recovery hints, optional playbooks, caching.
- **What we intentionally kept ours**: free LLM sequencing, engagement isolation, evidence grades, hard finalize.

```
┌─────────────────────────────────────────────────────────────┐
│  OpenCode (+ AGENTS.md instructions)                        │
│  Thinks, chooses tools, narrates, invents scripts           │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP (stdio)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  platform-mcp (FastMCP gateway)                             │
│  Session bind · typed recon/network tools · exec/shell/…    │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP → localhost:9000
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  backend (FastAPI)                                          │
│  Validate · build command · execute · parse · findings      │
│  Graph · gaps · finalize · exec cache · recovery hints      │
└───────────────┬─────────────────────────────┬───────────────┘
                │ docker exec                 │ SQL
                ▼                             ▼
┌───────────────────────────┐   ┌─────────────────────────────┐
│  ai-pentest-kali          │   │  Postgres                   │
│  mcp-servers + binaries   │   │  engagements, findings,     │
│  (nmap, subfinder, …)     │   │  asset_nodes / edges, runs  │
└───────────────────────────┘   └─────────────────────────────┘
```

Start stack:

```bash
cd llmwork/AI-Pentesting-Tool
docker compose up -d
```

OpenCode loads `opencode.json` → MCP server `platform-mcp/server.py` → `PENTEST_API_BASE=http://localhost:9000`.

---

## 2. Repository layout

| Path | Purpose |
|------|---------|
| `backend/` | FastAPI API, execution pipeline, stores, finalize |
| `platform-mcp/` | What OpenCode sees: gateway + typed recon/network tools |
| `mcp-servers/` | Per-category tool wrappers (`recon/`, `network/`, `web/`, … + `_core/`) |
| `kali-tools/` | Kali Docker image (binaries + PATH) |
| `config/` | Tool catalog YAML, playbooks, workflows, escalation, tech dispatch |
| `skills/` | Methodology markdown (assistive, not auto-run) |
| `scripts/` | Smoke tests (`smoke_recon_network.py`, …) |
| `AGENTS.md` | Primary LLM contract (loaded by OpenCode) |
| `opencode.json` | MCP wiring + timeouts |
| `docker-compose.yml` | postgres + kali-tools + backend |

---

## 3. Session lifecycle

1. **`platform_set_target(target="example.com", force_new=?)`**  
   Resolves/creates an **engagement** (isolated memory). Short names trigger clarification.
2. **`platform_health` / `platform_context`**  
   Backend health + inferred focus, gaps, graph/findings summary, finalize readiness.
3. **Work** — typed tools / `platform_exec` / shell / script; mirror with `platform_think`.
4. **Memory** — `platform_findings`, `platform_record_finding`.
5. **Close** — `platform_finalize_check` → `complete` or `partial_only`.

Everything after bind is scoped to `engagement_id`. Switching targets rebinds; do not mix engagements in one narrative.

---

## 4. How tools work

### 4.1 Preference order (elite path)

| Priority | Mechanism | When |
|----------|-----------|------|
| 1 | **Typed recon/network MCP tools** | `subfinder_scan(domain=…)`, `nmap_syn_scan(target=…)`, `rustscan_fast_scan(…)`, … |
| 2 | **`platform_exec`** | Any catalog tool; params object or JSON string |
| 3 | **`platform_shell`** | Single allowlisted binary + argv (no `;|&`$()<>`) |
| 4 | **`platform_script`** | Invent / batch / pipes / multi-step logic |

Shell is an **escape hatch**, not the default. Aliases are fixed: `target|domain|host|url` remap automatically.

### 4.2 Listing tools

- **`platform_tools(query=, category=)`** → `GET /api/v1/tools/catalog`  
  Shows registered names, category, **OK / MISSING** vs Kali binaries.
- Typed tools also appear **directly** in OpenCode’s MCP tool list (~26 recon+network).
- Full wrapper surface (~90) lives under `mcp-servers/` (web, vuln, cloud, …) — reachable via `platform_exec` when registered in the backend catalog.

### 4.3 Execution pipeline (catalog tools)

```
LLM call (typed or platform_exec)
  → platform-mcp POST /api/v1/mcp/execute
  → tool_execution.execute_tool_request
       · resolve engagement/run
       · governance (permissive)
       · inject engagement seed if no target-like params
       · param_validator + agent_arg_normalizer (aliases, bools, ports)
       · reject empty primary (clear 400, not silent empty CLI)
       · engagement exec_cache (TTL ~1h) → cache_hit / cache_key (force_refresh=true bypasses)
       · command_builder (loads mcp-servers/*/tools/*.py)
       · mcp_client → docker exec Kali → run binary
       · summarize → findings + graph ingest
       · **universal ingest_rules** (YAML) → auto-promote banners/Oracle/SPA demotion
       · recovery: next_hint + fallback_tools (fail / timeout / empty stdout)
  → mirrored text back to OpenCode (COMMAND, STDOUT, TRY NEXT, …)
```

### 4.3b Elite operator verbs (beyond OpenCode’s old friction)

| Verb | Purpose |
|------|---------|
| `platform_skills` / `platform_config` | Skills & allowlisted YAML are **visible** (no more “skills invisible”) |
| `platform_graph_query` | Filter graph by type/substring — not summary-only |
| `platform_crown_jewels` | Rank VPN/mail/Oracle/admin from evidence |
| `platform_fanout_assets` | Batch **your** shortlist (dry-run default) |
| `platform_job_start` / `poll` / `result` | Parallel branches for long tools (job_id) |
| `force_refresh` on `platform_exec` | Cache transparency + intentional re-run |
| Finalize `spa_false_api_claims` | HTML catch-all on `/api` cannot support COMPLETE CRITICAL theater |

Config: `config/ingest_rules.yaml`, `config/thinking_model.yaml` · skill: `skills/shared/evidence-to-hypothesis.md`
(No per-vendor packs — extend signal classes in YAML; LLM supplies product knowledge.)

Key files:

- `platform-mcp/server.py`, `platform-mcp/typed_recon_network.py`
- `backend/.../tool_execution.py`, `param_validator.py`, `agent_arg_normalizer.py`
- `backend/.../command_builder.py`, `mcp_client.py`, `exec_cache.py`
- `mcp-servers/_core/executor.py`, `runner.py`
- `config/recon_network_tools.yaml`

### 4.4 Param aliases (why wrappers no longer “feel broken”)

Agents often send `target` while the CLI expects `domain` (or the reverse).

Before run, the platform maps:

- Domain tools (`subfinder_scan`, `amass_scan`, `dnsenum_scan`, …) ← `domain|target|host|url`
- Host tools (`nmap_*`, `rustscan_*`, …) ← `target|host|domain`
- URL tools (`hakrawler_crawl`, …) ← `url|target|…`

Empty primary → **hard fail with a clear message**, not `subfinder -d` with exit 0 and zero results.

### 4.5 Shell & script playground

| Tool | Behavior |
|------|----------|
| `platform_shell` | One binary + args in Kali; findings may still be recorded from stdout |
| `platform_script` | Python/bash in `/tmp/pentest/<engagement_id>/`; optional `packages=` pip install |
| `platform_install` | Install packages into the Kali env for scripts |
| `platform_fanout` | Optional sister-domain batch helper (dry-run by default) |

Pipes, loops, and compound shell → use **script**, not shell metacharacters.

### 4.6 Recovery & caching

- On **fail / timeout / empty success**: response includes `next_hint` and `fallback_tools` (escalation matrix + static recon/network fallbacks).
- **Exec cache**: same engagement + tool + canonical params within ~1h → `cache_hit=true` (change params to force a fresh run).

### 4.7 Advisory playbooks (not locked chains)

`platform_playbook(name=, target=)` reads `config/playbooks.yaml` (+ `.json`).

Examples: `web_recon_light`, `network_crown_jewels`, `dns_deep`, `smb_followup`.

Returns ordered steps `{tool, why, suggested_params, fallback}` — **nothing auto-runs**. The LLM may follow, edit, or ignore.

Optional multi-step **workflows** also exist in `config/workflows.yaml` (API/workflow runner); they are not forced in the OpenCode loop.

---

## 5. Memory: engagements, findings, graph

### 5.1 Engagement

One root target → one engagement (unless `force_new=true`). Isolates:

- Findings
- Graph nodes/edges
- Tool coverage / runs
- Script artifacts under `/tmp/pentest/<engagement_id>/`

### 5.2 Findings

Stored structured facts with:

| Field | Role |
|-------|------|
| `finding_type` | subdomain, host, url, port, service, technology, observation, … |
| `evidence_grade` | `observed` \| `inferred` \| `unverified` |
| `claim_severity` | clamped by grade (no CRITICAL from DNS alone) |
| `raw_data` / `evidence` | proof snippets for finalize honesty |

Sources:

- Auto-parse after tool/shell/script runs
- Manual: `platform_record_finding` (use when chat saw proof the parser missed)

MCP: `platform_findings` → list/summary for operator + LLM.

### 5.3 Evidence grades

| Grade | Meaning | Max severity |
|-------|---------|--------------|
| `observed` | Banner, HTTP body, verified probe | CRITICAL/HIGH **with substantive raw proof** |
| `inferred` | DNS, CT, open port without verify | MEDIUM |
| `unverified` | Noise, unparsed, port-flood / honeypot | INFO |

Port-flood hosts are downgraded until a few services are actually verified.

### 5.4 Engagement graph

- **Nodes**: domains, hosts, IPs, services, URLs, …  
- **Edges**: resolves-to, hosts, related, …  
- Built by ingesting findings (`engagement_graph` service).
- Feeds attack-surface / network-surface trees and pivot hints (e.g. siblings on same IP).
- Graph is **engagement-wide** (not wiped when `run_id` changes).

### 5.5 Context for the agent

`platform_context` → hybrid context:

- Inferred focus (advisory — not a hardcoded stage)
- Coverage gaps
- Findings summary + graph summary
- Finalize readiness banner
- Short skills excerpt + tooling brief

---

## 6. Finalize gate (honest reporting)

`platform_finalize_check` → `finalize_readiness.py`.

| Mode | Meaning |
|------|---------|
| `complete` | Enough structured **observed** evidence; no blocking gaps |
| `partial_only` | Report progress only — do **not** title COMPLETE / CVE theater |

Blocking examples:

- Surface too shallow / evidence too thin
- Unverified HIGH claims
- Port-flood unverified
- **`weak_critical_claims`** — CRITICAL/CVE-shaped claims without strong observed body/banner proof
- Structured observed count too low

Operator override exists but must still label unverified claims clearly.

This is the platform’s main advantage over “raw HexStrike JSON → COMPLETE.”

---

## 7. Skills & assistance (how the LLM is guided)

### 7.1 `AGENTS.md` (primary)

Loaded by OpenCode as instructions. Defines:

- Tool preference table
- Evidence grades + finalize rules
- Playbooks, timeouts, visibility (`platform_think`, narrate in chat)
- Safety (authorized targets only)

### 7.2 `skills/` (methodology packs)

Markdown under `skills/commander/`, `skills/recon/`, `skills/network/`, … plus `skills/shared/`.

Loaded into context via the backend skills loader — **hints**, not forced checklists.

Commander mindset:

- Evidence over narrative
- Adaptive depth (deepen crown jewels vs hostname spam)
- Prefer typed tools; shell for invention
- Honor finalize BLOCKED

### 7.3 Config assistants

| File | Role |
|------|------|
| `config/recon_network_tools.yaml` | Tasks, params, llm_hints for recon/network |
| `config/playbooks.yaml` | Advisory sequences |
| `config/workflows.yaml` | Optional multi-step workflows |
| `config/escalation_matrix.yaml` | Failure → alternate tools (TRY NEXT) |
| `config/tech_dispatch.yaml` | Tech signal → suggested next tasks |

### 7.4 Visibility helpers

| Tool | Role |
|------|------|
| `platform_think` | Mirror hypothesis/plan to the operator |
| `platform_findings` | Sync stored memory into chat |
| Exec mirrors | COMMAND / STDOUT / TRY NEXT / cache_hit |

The operator cannot see private chain-of-thought — the agent must **write** reasoning in chat and use these mirrors.

---

## 8. Flexibility model

```
Typed catalog tools (reliable, cached, graded)
        │
        ├── free LLM sequencing (no mandatory chains)
        │
        ├── advisory playbooks / gaps / escalations
        │
        └── escape hatches
              ├── platform_shell  (one binary)
              ├── platform_script (invent anything)
              └── platform_install (pip for scripts)
```

**Flexible:** tool order, invention, playbook ignore/edit, script playground.  
**Not flexible (by design):** evidence grades, severity clamp, finalize honesty, engagement isolation, shell metachar ban (use script instead).

---

## 9. Kali / Docker

- Image: `kali-tools/Dockerfile` → container `ai-pentest-kali`
- Go tools under `/opt/go/bin`, symlinked to `/usr/local/bin`; `whois` + `rustscan` included
- Availability checks resolve binaries **inside Kali** (not the backend container)
- Backend mounts docker.sock to `docker exec` into Kali

Smoke proof:

```bash
python scripts/smoke_recon_network.py --api http://127.0.0.1:9000
```

---

## 10. Typical engagement pattern

1. `platform_set_target` (+ `force_new` if fresh)
2. `platform_think` + `platform_context` + optional `platform_playbook`
3. Passive recon: typed `subfinder_scan` / `whois_lookup` / `domain_hunter` / `amass_scan`
4. Live probe: `httpx_probe` or script for bulk
5. Network: `rustscan_fast_scan` → chunked `nmap_*` (avoid huge `-sV` one-shots)
6. Deepen crown jewels with `platform_script` + `platform_record_finding(evidence=…)`
7. `platform_findings` often
8. `platform_finalize_check` — ship **PARTIAL** or deepen until COMPLETE is honest

---

## 11. MCP tool cheat sheet

**Session:** `platform_set_target`, `platform_health`, `platform_think`, `platform_context`  

**Catalog:** `platform_tools`, typed `*_scan` / `*_probe`, `platform_exec`  

**Invent:** `platform_shell`, `platform_script`, `platform_install`, `platform_fanout`  

**Advise:** `platform_playbook`  

**Memory / report:** `platform_findings`, `platform_record_finding`, `platform_finalize_check`

---

## 12. What “elite” means here

| Layer | Behavior |
|-------|----------|
| Execution | Typed params + aliases + recovery hints + cache |
| Strategy | Free LLM brain + advisory playbooks/gaps |
| Memory | Engagement graph + graded findings |
| Reporting | Finalize blocks CVE/COMPLETE theater without proof |
| Invention | Script/shell when catalog is not enough |

The platform assists an elite operator — it does not replace judgment. SPA catch-alls returning HTTP 200 for `/api/*` still need body proof before CRITICAL.

---

## 13. Reload after code changes

1. `docker compose restart backend` (or recreate if needed)
2. Reload OpenCode MCP / start a **new chat** so typed tools and `AGENTS.md` refresh
3. Optional: re-run `scripts/smoke_recon_network.py`

---

*This document matches the post–elite-plan architecture (typed recon/network MCP, playbooks, recovery, exec cache, weak-CRITICAL finalize gate, AGENTS/skills rewrite).*
