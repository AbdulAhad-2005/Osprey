# Developer Guide — Explore & Optimize the System

> **Purpose:** A practical map for reviewing the recon→network pipeline: how OpenCode connects, how data flows, which files to read, and in what order — so you can optimize with confidence.
>
> **Audience:** Developers modifying the platform (vs [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) for operators).
> **Related:** [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md), [`../AGENTS.md`](../AGENTS.md)

---

## 1. Big picture (one paragraph)

OpenCode is the **Commander** (brain). It never talks to nmap/subfinder directly. It talks only to a small local MCP server (`platform-mcp`), which calls the FastAPI backend on port **9000**. The backend validates and governs the request, runs the tool inside the **Kali** container, parses stdout into **findings**, updates the **engagement graph**, then returns hybrid hints. The next turn OpenCode calls `platform_context` and sees coverage gaps, attack-surface tree, and skills — then picks the next tool. One **engagement** = one root domain (isolated Postgres storage). One **run** = one work session on that engagement.

```
User chat
   │
   ▼
OpenCode  +  AGENTS.md instructions
   │  MCP (stdio)
   ▼
platform-mcp/server.py     ← session: target, engagement_id, run_id
   │  HTTP httpx
   ▼
FastAPI backend :9000
   │
   ├─ engagements / hybrid context / findings
   ├─ tool_execution → Kali docker exec → mcp-servers/*
   └─ parsers → Postgres (findings + graph + coverage)
```

---

## 2. How OpenCode is connected (steps that were taken)

### 2.1 Config file

| Item            | Path / value                                                        |
| --------------- | ------------------------------------------------------------------- |
| OpenCode config | Workspace root: `opencode.json` (or global `~/.config/opencode/opencode.json`) |
| Instructions    | `AGENTS.md` (repo root)                                           |
| MCP server name | `pentest-platform`                                                |
| MCP command     | `python` → `platform-mcp/server.py`                             |
| API base        | `PENTEST_API_BASE=http://localhost:9000`                          |

OpenCode starts the MCP process locally (not Docker). The MCP process talks to the Dockerized backend.

### 2.2 What OpenCode is allowed to call

OpenCode sees ~50 MCP tools defined in `platform-mcp/` (full list in [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md); families in [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md)). The backbone few and where they land:

| MCP tool                              | Job                                   | Backend                                                             |
| ------------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| `platform_set_target(target)`       | Bind/switch root domain → engagement | `POST /api/v1/engagements/resolve` + `.../runs/ensure`          |
| `platform_health(target=?)`         | Health + optional bind                | `GET /health`                                                     |
| `platform_context(phase, target=?)` | Brain packet (gaps, crown jewels, delta) | `GET /api/v1/hybrid/context[/{phase}]`                        |
| typed `*_scan`/`*_probe`, `platform_exec` | Run one Kali tool                 | `POST /api/v1/mcp/execute`                                        |
| `platform_shell` / `platform_script` | Allowlisted binary / sandboxed code | `POST /api/v1/mcp/{shell,script}`                                 |
| `platform_fanout(...)`              | Explicit sister subfinder batch       | `POST /api/v1/engagements/{id}/actions/enumerate-pending-sisters` |
| memory tools (`platform_graph_link`, `platform_memory_search`, …) | Read/write the notebook | `/api/v1/hybrid/*`                                    |

**Rule:** Never wire OpenCode to raw `mcp-servers/recon` or `network` servers. Those are Kali-side only, reached through the backend.

### 2.3 Session binding (dynamic targets)

Inside the MCP process (in-memory):

- `_SESSION_TARGET` — active root domain
- `_SESSION_ENGAGEMENT_ID` — Postgres engagement
- `SESSION_RUN_ID` — this OpenCode/MCP process session

When the user names a **new** domain → `platform_set_target` → resolve/create engagement → new isolated storage. Same domain later → reuse that engagement’s memory.

### 2.4 Docker stack (must be up)

From the repo root:

```powershell
docker compose up -d
```

| Service    | Container               | Port                             |
| ---------- | ----------------------- | -------------------------------- |
| postgres   | `ai-pentest-postgres` | host`5432` or `5433` → 5432 |
| kali-tools | `ai-pentest-kali`     | none published                   |
| backend    | `ai-pentest-backend`  | **9000**                   |

`platform-mcp` is **not** a compose service — OpenCode starts it.

---

## 3. End-to-end pipeline (one tool run)

Trace this path when debugging or optimizing:

```
1. OpenCode: platform_set_target("example.com")
2. OpenCode: platform_context(phase="full")
3. OpenCode: platform_exec("subfinder_scan", {"domain":"example.com"})
4. MCP → POST /api/v1/mcp/execute
5. tool_execution.execute_tool_request:
     a. tool_registry — is tool known?
     b. session_context — bind engagement_id + run_id
     c. governance — permissive pass-through today (scope/ROE enforcement is on the roadmap)
     d. param_validator — normalize params
     e. command_builder — preview CLI
     f. mcp_client — docker exec into Kali → mcp-servers/<cat>/server.py
     g. summary_agent — parse stdout → Finding list
     h. findings_store.add_many → Postgres
     i. engagement_graph.ingest → nodes/edges
     j. tool_coverage_store.record (soft mark)
     k. hybrid hints (escalation, pivots, dispatch)
     l. audit_log
6. Response → OpenCode (stdout + finding_titles + hybrid)
7. OpenCode: platform_context again → gaps/tree updated → next decision
```

**Design principle:** Backend **remembers and advises**. OpenCode **decides**. Gaps do not force tool chains.

---

## 4. Directory map (what lives where)

```
AI-Pentesting-Tool/           # repo root
├── AGENTS.md                 # OpenCode operator prompt
├── docker-compose.yml
├── .env
├── opencode.json             # MCP wiring (or use global ~/.config/opencode/opencode.json)
├── platform-mcp/
│   ├── server.py             # MCP façade (~50 tools)
│   ├── typed_recon_network.py
│   └── typed_tech_identification.py
├── config/                   # YAML levers
│   ├── recon_network_tools.yaml
│   ├── escalation_matrix.yaml
│   ├── tech_dispatch.yaml
│   ├── ingest_rules.yaml
│   ├── thinking_model.yaml
│   └── workflows.yaml
├── skills/                   # Markdown playbooks
│   ├── commander/  recon/  network/  summary/  shared/  …
├── backend/src/pentest_platform/
│   ├── main.py
│   ├── api/v1/               # HTTP routes
│   ├── services/             # Core logic (tool_execution, engagement_graph, …)
│   ├── models/               # SQLAlchemy tables
│   ├── schemas/              # Pydantic
│   └── services/parsers/     # parser registry
├── mcp-servers/              # Kali-side tool adapters
│   ├── recon/  network/  web/  vuln/  cloud/  …
└── docs/
    └── DEVELOPER_GUIDE.md    ← this file
```

---

## 5. Recommended reading order (for analysis & optimization)

Read in this order. Do **not** start randomly in `mcp-servers/` or Alembic.

### Pass A — Contract & loop (1–2 hours)

| # | File                                                | Why                         |
| - | --------------------------------------------------- | --------------------------- |
| 1 | `AGENTS.md`                                       | What OpenCode is told to do |
| 2 | `skills/pipeline/full-attack-surface-pipeline.md` | 8-stage methodology         |
| 3 | `skills/commander/planning-rules.md`              | When to reopen recon / skip |
| 4 | `platform-mcp/server.py`                          | Exact MCP ↔ HTTP mapping   |
| 5 | `docs/ARCHITECTURE.md`                            | How the pieces fit + why    |

**Ask yourself:** Is the Commander loop clear? Where do skills over-promise vs what backend actually enforces?

### Pass B — Session, engagement, isolation (1–2 hours)

| #  | File                                                               | Why                                         |
| -- | ------------------------------------------------------------------ | ------------------------------------------- |
| 6  | `services/session_context.py`                                    | Target → engagement bind / switch          |
| 7  | `services/engagement_store.py`                                   | Postgres engagements                        |
| 8  | `services/run_store.py`                                          | run_id ↔ engagement                        |
| 9  | `api/v1/endpoints/engagements.py`                                | `/resolve`, tree, network-surface, fanout |
| 10 | `models/engagement.py`, `models/run.py`, `models/finding.py` | Schema                                      |

**Ask yourself:** Can two targets ever mix? What happens if `engagement_id` is missing?

### Pass C — Execute kernel (half day — highest leverage)

| #  | File                            | Why                                   |
| -- | ------------------------------- | ------------------------------------- |
| 11 | `api/v1/endpoints/mcp.py`     | Thin execute entry                    |
| 12 | `services/tool_execution.py`  | **Whole pipeline in one place** |
| 13 | `services/governance.py`      | What is hard-blocked                  |
| 14 | `services/param_validator.py` | Param normalization                   |
| 15 | `services/command_builder.py` | CLI assembly, nmap flags              |
| 16 | `services/mcp_client.py`      | Docker exec → Kali                   |
| 17 | `services/tool_registry.py`   | Hardcoded tool catalog                |
| 18 | `services/task_registry.py`   | YAML capabilities for LLM             |

**Ask yourself:** Timeouts, retries, caching, preview vs real command, error paths.

### Pass D — Parse → memory → graph (half day — quality of “brain”)

| #  | File                                  | Why                                |
| -- | ------------------------------------- | ---------------------------------- |
| 19 | `services/summary_agent.py`         | Parser = ground truth              |
| 20 | `services/parsers/recon_network.py` | subfinder/httpx/nmap/domain_hunter |
| 21 | `services/findings_store.py`        | Persist + summaries                |
| 22 | `services/engagement_graph.py`      | Nodes/edges, pivots, CF flags      |
| 23 | `services/tool_coverage_store.py`   | Soft “already ran” marks         |

**Ask yourself:** What stdout shapes break parsers? ANSI color junk? Missing `resolves_to` / IP edges?

### Pass E — What Commander sees next (gaps & surfaces)

| #  | File                                                                    | Why                            |
| -- | ----------------------------------------------------------------------- | ------------------------------ |
| 24 | `services/coverage_engine.py`                                         | Soft gaps (sisters, IPs, CF…) |
| 25 | `services/attack_surface_tree.py`                                     | Seed→sisters→hosts tree      |
| 26 | `services/network_surface.py`                                         | Per-IP ports/services          |
| 27 | `services/commander_context.py`                                       | Assembles full packet          |
| 28 | `api/v1/endpoints/hybrid.py`                                          | Context API                    |
| 29 | `services/phase_reflection.py`                                        | Coarse phase checks            |
| 30 | `services/escalation_registry.py` + `config/escalation_matrix.yaml` | Fail → suggest                |
| 31 | `services/tech_dispatch.py` + `config/tech_dispatch.yaml`           | Signal → task                 |

**Ask yourself:** Are gaps high-signal or noisy? Is CF origin hunt only a flag? Is tree truncated too aggressively?

### Pass F — Kali tool adapters (as needed)

| #  | Location                                              | Why                                   |
| -- | ----------------------------------------------------- | ------------------------------------- |
| 32 | `mcp-servers/recon/tools/`                          | How each recon tool is wrapped        |
| 33 | `mcp-servers/network/` (`nmap_wrapper.py`, tools) | Network execution surface             |
| 34 | `config/recon_network_tools.yaml`                   | Defaults, skill_file links, LLM hints |

**Ask yourself:** Wrong defaults? Missing `additional_args` escape hatch? Timeout too low?

### Pass G — Skills & optional paths

| #  | File                                               | Why                                             |
| -- | -------------------------------------------------- | ----------------------------------------------- |
| 35 | `skills/recon/*`, `skills/network/*`           | Phase playbooks                                 |
| 36 | `services/skills_loader.py`                      | How skills enter context                        |
| 37 | `services/fanout.py`                             | Explicit sister fan-out                         |
| 38 | `config/workflows.yaml` + `workflow_runner.py` | Structured workflows (not OpenCode default)     |
| 39 | `api/v1/endpoints/agent.py` + orchestrator       | Alternate LiteLLM agent path (not OpenCode MCP) |

---

## 6. Two paths that coexist (don’t confuse them)

| Path                         | Entry                                                      | Used by                  |
| ---------------------------- | ---------------------------------------------------------- | ------------------------ |
| **OpenCode Commander** | `platform-mcp` → `/mcp/execute` + `/hybrid/context` | Primary interactive path |
| **Backend agent chat** | `POST /api/v1/agent/chat` → orchestrator / LiteLLM      | Optional CLI/API agent   |

When optimizing for OpenCode, focus on **platform-mcp + tool_execution + context builders**. The agent chat path can differ.

---

## 7. What is hard-enforced vs soft-guided

### Hard (backend refuses or isolates)

- Engagement bind for findings persistence
- Multi-target isolation by `engagement_id`
- Param validation (shell-metacharacter ban)
- Scan budget (blocks full-range `-p-` / `1-65535` without `confirm_expensive`)
- Evidence-grade severity clamp + finalize gate on weak claims
- Fan-out only with `dry_run=false` **and** `confirm=true`
- No silent auto-chain after `domain_hunter`

> **Not yet hard:** scope/ROE **governance is permissive today** (approves all tools). Real enforcement is reliability-plan Phase 1 — see [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md).

### Soft (advice only)

- Coverage gaps (`host_cf_no_origin`, `ip_unscanned`, …)
- Attack-surface tree / network surface text
- Graph pivots
- Skills 8-stage order
- Escalation / tech_dispatch suggestions

**Optimization implication:** Improving parsers/graph/gaps improves Commander decisions without building a rigid state machine. Building a forced stage machine is a separate product decision.

---

## 8. Data store (where results live)

| Store           | What                                                                                           |
| --------------- | ---------------------------------------------------------------------------------------------- |
| Postgres tables | `engagements`, `runs`, `findings`, `asset_nodes`, `asset_edges`, `tool_coverage`   |
| Docker volume   | `ai-pentesting-tool_postgres_data`                                                           |
| View via API    | `/api/v1/engagements/`, `/findings/`, `/engagements/{id}/tree`, `/hybrid/context/full` |
| View via SQL    | `docker exec -it ai-pentest-postgres psql -U pentest -d pentest`                             |
| Not stored      | OpenCode chat history                                                                          |

Readable summary (better than raw tree JSON):

```powershell
curl.exe -s "http://localhost:9000/api/v1/hybrid/context/full?engagement_id=<ID>"
```

---

## 9. How to analyze in practice (workflow)

### Step 1 — Run one controlled engagement

1. `docker compose up -d`
2. Open OpenCode with `opencode.json` MCP enabled
3. `platform_set_target("example.com")` → note `engagement_id`
4. `platform_context(phase="full")` → save response
5. One `platform_exec` (e.g. subfinder) → note findings
6. `platform_context` again → see what changed

### Step 2 — Diff memory

```sql
SELECT finding_type, source_tool, COUNT(*)
FROM findings WHERE engagement_id = '<ID>'
GROUP BY 1, 2;
```

```powershell
curl.exe -s "http://localhost:9000/api/v1/engagements/<ID>/tree?condensed=true"
curl.exe -s "http://localhost:9000/api/v1/engagements/<ID>/network-surface"
```

### Step 3 — Trace one bug class

| Symptom                                  | First files to open                                               |
| ---------------------------------------- | ----------------------------------------------------------------- |
| Findings empty / wrong engagement        | `session_context.py`, `tool_execution.py`, MCP headers        |
| Tool “runs” but no structured findings | `parsers/recon_network.py`, `summary_agent.py`                |
| Gaps wrong / noisy                       | `coverage_engine.py`, graph edges in `engagement_graph.py`    |
| Tree empty IPs/ports                     | parsers + graph ingest for`resolves_to` / `has_port`          |
| Command wrong / timeout                  | `command_builder.py`, `mcp_client.py`, tool timeout in MCP    |
| OpenCode ignores stages                  | `AGENTS.md`, skills, what `platform_context` actually returns |

### Step 4 — Optimize in this priority order

1. **Parsers → graph quality** (garbage in → garbage gaps)
2. **Coverage gaps signal quality** (fewer, higher confidence)
3. **Context packet size/clarity** (`commander_context`, condensed tree)
4. **Tool defaults / timeouts** (YAML + command_builder)
5. **Skills wording** (don’t contradict soft-gap model)
6. **Origin-hunt / Stage 6** (currently flag-only — `host_cf_no_origin` has no `suggested_tool`)
7. **UI / reporting** (optional; not required for pipeline correctness)

---

## 10. High-leverage files for “make it the best”

If you only deep-dive ten files:

1. `platform-mcp/server.py`
2. `services/tool_execution.py`
3. `services/session_context.py`
4. `services/parsers/recon_network.py`
5. `services/engagement_graph.py`
6. `services/coverage_engine.py`
7. `services/commander_context.py`
8. `services/attack_surface_tree.py`
9. `services/network_surface.py`
10. `config/recon_network_tools.yaml` + `AGENTS.md`

---

## 11. Mental model cheat sheet

| Concept                       | Meaning                                        |
| ----------------------------- | ---------------------------------------------- |
| **Engagement**          | Durable bucket for one root domain             |
| **Run**                 | One MCP/OpenCode session under that engagement |
| **Finding**             | Parsed fact from a tool                        |
| **Graph**               | Nodes/edges linking assets                     |
| **Coverage gap**        | Soft “maybe incomplete” per asset            |
| **Attack surface tree** | Human/LLM-readable hierarchy                   |
| **Network surface**     | Per-IP ports/services readiness                |
| **Commander**           | OpenCode deciding next tool from context       |

---

## 12. Restart / reload reminder

| Change                                          | Action                                                    |
| ----------------------------------------------- | --------------------------------------------------------- |
| Backend Python (volume-mounted)                 | Often hot-reload; else`docker compose restart backend`  |
| `.env` / compose                              | `docker compose up -d --force-recreate`                 |
| `platform-mcp/server.py` or `opencode.json` | Restart OpenCode / reload MCP                             |
| Dockerfile / deps                               | `docker compose up -d --build --force-recreate backend` |

---

## 13. Suggested analysis checklist (print this)

- [ ] I can draw OpenCode → MCP → backend → Kali → Postgres without notes
- [ ] I know which MCP tools exist and which endpoints they hit
- [ ] I can explain engagement vs run
- [ ] I traced one `platform_exec` through `tool_execution.py`
- [ ] I know which parsers exist and what they miss
- [ ] I know which gaps are soft and which rules are hard
- [ ] I can name my top 3 optimization bets (parsers / gaps / context / tools)
- [ ] I verified with a live `engagement_id` via API or psql

---

*This guide is the map. Optimization starts with Pass C + Pass D (execute + parse/graph) — that is where Commander quality is won or lost.*
