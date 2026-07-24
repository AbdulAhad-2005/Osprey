# Architecture & Workflow

> **Audience:** Anyone evaluating how the platform works and *why* it is built this way — developers, operators, stakeholders.
> **Scope:** The current build (recon + network / enum phases). Web, vuln, exploit, cloud, and binary phases are planned — see [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md) and the vision in [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md).
> **Related:** [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) (operator) · [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md) (code map) · [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) (per-tool reference) · [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) (APIs)

---

## 1. The one-sentence idea

**An external LLM (OpenCode) is the brain; the platform is a lab + referee + shared notebook.** You describe a target in plain English; the LLM chooses security tools from a governed catalog, runs them in Kali via MCP, reads the full output, adapts, writes typed findings into a durable engagement graph, and reports back — while YAML config and markdown skills *assist* it, not *script* it.

> **Motto:** We do not hardcode the engagement. We give the LLM trustworthy memory, safe execution primitives, transparent policy, and complete provenance so it can become an elite operator.

---

## 2. High-level architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  OpenCode (the Commander / brain)  +  AGENTS.md operator prompt   │
│  Thinks, chooses tools, narrates, invents scripts, decides stop   │
└───────────────────────────────┬──────────────────────────────────┘
                                │ MCP (stdio)
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  platform-mcp/server.py  (FastMCP gateway, ~50 tools)             │
│  Session bind · typed recon/network tools · memory/notebook ·     │
│  exec / shell / script / jobs / fanout                            │
└───────────────────────────────┬──────────────────────────────────┘
                                │ HTTP → localhost:9000
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  backend (FastAPI :9000)                                          │
│  ONE execution kernel: govern · validate · scan-budget · cache ·  │
│  build command · execute · parse → findings · ingest → graph ·    │
│  coverage · recovery hints · audit                                │
└───────────────┬──────────────────────────────────┬───────────────┘
                │ docker exec                        │ SQL
                ▼                                    ▼
┌───────────────────────────┐        ┌──────────────────────────────┐
│  ai-pentest-kali          │        │  Postgres                    │
│  mcp-servers/* + binaries │        │  engagements · runs ·        │
│  (nmap, subfinder, httpx…)│        │  findings · asset_nodes ·    │
│                           │        │  asset_edges · tool_coverage │
└───────────────────────────┘        └──────────────────────────────┘
```

### Four conceptual roles

| Role | Responsibility | Where it lives |
|------|----------------|----------------|
| **Lab** | Tools, allowlisted shell, custom scripts, jobs, fanout, artifacts | `mcp-servers/`, `kali-tools/`, exec/shell/script services |
| **Shared notebook** | Executions, findings, engagement graph, evidence, decisions | `findings_store`, `engagement_graph`, Postgres |
| **Referee** | Scope/governance, scan budget, evidence law, report integrity | `governance`, `scan_budget`, `schemas/finding.py`, `finalize_*` |
| **Brain (LLM)** | Which tool, what flags, relation meaning, confirmation, stopping | OpenCode + `AGENTS.md` + `skills/` |

This split is the product's core bet: **config owns safety and defaults; cognition belongs to the LLM.** It was synthesized from analyzing Shannon (durable phases + validation rigor), the Shannon OpenCode plugin (LLM-as-orchestrator + Docker tools), Dark-Moon (reactive chaining + `additional_args` freedom + MCP gatekeeper), and HexStrike (broad Kali tool surface + command recipes) — keeping the best of each. See [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md).

---

## 3. The primary path vs the demoted path

There are two LLM-driver paths in the tree. **Only the first is the current product.**

| Path | Entry | Status |
|------|-------|--------|
| **① OpenCode → platform-mcp → backend** | `platform-mcp/server.py` → `/api/v1/mcp/*` + `/api/v1/hybrid/*` | **Primary.** The brain is external (OpenCode / Claude Desktop / any MCP client). |
| **② Backend built-in agent loop + CLI** | `POST /api/v1/agent/chat` → `agent_loop.py` (LiteLLM ReAct) + `cli/` | **Demoted.** Off by default (`ENABLE_BUILTIN_AGENT=false`); the YAML `workflow_runner` is likewise off (`ENABLE_WORKFLOWS=false`). Kept for optional local/API driving. |

Both paths funnel through the **same execution kernel** (`tool_execution.py`), so governance, parsing, and memory behave identically regardless of driver. When reasoning about the product, think path ①.

---

## 4. From prompt to tool command (path ①)

Example: the LLM calls `httpx_probe(target="scanme.nmap.org")`.

```
1. platform_set_target("scanme.nmap.org")
      → POST /api/v1/engagements/resolve → engagement_id (isolated Postgres storage)
2. platform_context()  → gaps, crown jewels, jobs, delta (a small brain packet)
3. httpx_probe(target=…)  [typed MCP tool]
      → platform-mcp POST /api/v1/mcp/execute
4. tool_execution.execute_tool_request:
      a. resolve engagement/run + inject seed target if the LLM omitted it
      b. governance check            (currently permissive — see §6)
      c. param_validator             (blocks shell metacharacters only)
      d. scan_budget                 (blocks full-range -p- / 1-65535 w/o confirm)
      e. exec cache                  (same engagement+tool+params within ~1h → cache_hit)
      f. command_builder             (loads mcp-servers/recon/tools/httpx_probe.py)
      g. mcp_client → docker exec ai-pentest-kali → httpx -u scanme.nmap.org …
      h. summarize_execution         (parsers → Finding objects) + apply_ingest_rules (YAML)
      i. findings_store + engagement_graph ingest → Postgres
      j. tool_coverage record · stdout artifact index · recovery hints · audit log
5. Response → OpenCode (stdout + finding_titles + soft next-hints)
6. Next turn: platform_context shows updated gaps → LLM decides the next move
```

**Critical design choice:** the LLM never sends raw shell. It sends **structured tool calls** (or an allowlisted single-binary `platform_shell`, or a sandboxed `platform_script`). The platform builds the CLI string. This gives full flag flexibility (any flags via `additional_args`) without arbitrary command injection.

---

## 5. The layers — what each does and why

### 5.1 platform-mcp gateway (`platform-mcp/server.py`)
The only surface OpenCode sees. ~50 tools in three families:
- **Memory / notebook:** `platform_context`, `platform_think`, `platform_graph_link[_many]`, `platform_tag_asset`, `platform_findings`, `platform_record_finding`, `platform_memory_search`, `platform_evidence_chain`, `platform_attempts`, `platform_crown_jewels`, `platform_thinking`, `platform_finalize_check`, `platform_report_outline`, `platform_artifact`.
- **Execution lanes:** typed `*_scan`/`*_probe` (36 recon/network), `platform_exec`, `platform_shell`, `platform_script`, `platform_install`, `platform_job_start/poll/result`, `platform_fanout[_assets]`.
- Session binding is in-process: one root target → one `engagement_id`; switching targets rebinds automatically to isolated storage.

### 5.2 Execution kernel (`services/tool_execution.py`)
One pipeline for every catalog tool (see §4). Single source of governance, validation, caching, parsing, coverage, and audit — so "works in one path but breaks in another" cannot happen.

### 5.3 Command builder (`command_builder.py` + `mcp-servers/*/tools/*.py`)
Per-tool `build_command()` functions harvested from HexStrike and hardened. The MCP tool module is the single source of truth for the actual CLI shape; the backend builder adds container-aware defaults (e.g. nmap falls back to `-sT -Pn --unprivileged` when raw sockets are unavailable).

### 5.4 Memory: findings + engagement graph (`findings_store.py`, `engagement_graph.py`)
Parsed outputs become typed `Finding` rows; the graph links assets (host → port → service, subdomain → domain, sibling-on-same-IP). All **durable in Postgres**, scoped per engagement so two targets never collide. This is the "shared notebook" that lets a long engagement survive context limits.

> **Known limitation (on the reliability roadmap):** background **jobs** and the **context delta** are still process-local (lost on backend restart). Findings and the graph are durable. See [`plans/ELITE_RELIABILITY_IMPLEMENTATION_PLAN.md`](./plans/ELITE_RELIABILITY_IMPLEMENTATION_PLAN.md).

### 5.5 Evidence law — the referee (`schemas/finding.py`)
Every finding carries an `evidence_grade` (`observed` / `inferred` / `unverified`) that **clamps** its `claim_severity`: unverified → INFO max, inferred → MEDIUM max, only observed can be CRITICAL. `platform_finalize_check` blocks a COMPLETE report on weak/CVE-shaped claims that lack observed proof. This is the platform's main advantage over "raw tool JSON → COMPLETE" tools.

### 5.6 Guidance: skills + config (`skills/`, `config/`)
Markdown skills (methodology) and YAML config (tool catalog, escalation matrix, tech dispatch, ingest rules, thinking-model scoring, playbooks) **advise** the LLM. Everything here is soft except the hard safety rails (scan budget, evidence clamp, finalize gate, shell-metacharacter ban).

### 5.7 Kali execution (`mcp_client.py` + `kali-tools/`)
Tools run inside the `ai-pentest-kali` container (NET_RAW/NET_ADMIN for SYN scans). The backend mounts the docker socket and `docker exec`s into Kali. Timed-out processes are killed and reaped so long scans can't leak process slots.

---

## 6. Design decisions (our way vs alternatives)

| Decision | Our choice | Why |
|----------|-----------|-----|
| Orchestration | **LLM orchestrator** (OpenCode) | Adapts to prompt, failures, target shape — vs a rigid fixed pipeline |
| Tool interface | **Structured tool calls + `additional_args`** | Same flag freedom as bash for scanning; none of the shell-injection risk |
| Skills/workflows | **Hints, not mandatory** | Assist like mature tools; don't force a YAML script |
| Execution paths | **One kernel** | One place for governance/parse/audit; no path drift |
| Runtime | **Docker Kali sidecar** | Reproducible tool versions, isolation, raw-socket capability |
| Model | **LiteLLM-agnostic** (demoted path) / any MCP client (primary) | Swap providers without rewriting the platform |
| Memory | **Durable typed graph + evidence grades** | The differentiator none of the reference tools fully have |

**Governance note (accurate current state):** the governance engine is presently a **permissive pass-through** — it approves every tool and records `governance_decision=approved` for audit compatibility. Real scope/ROE enforcement is the first item on the reliability roadmap. Docs and `AGENTS.md` describe scope discipline as operator guidance, but the backend does not yet *block* out-of-scope targets.

---

## 7. What worked, what failed, what we fixed (recon/network build)

**Worked as designed:** autonomous tool choice and ordering; adaptation after a timeout (full `-p-` → targeted port list); durable memory across turns; evidence-graded findings; honest finalize gating; multi-target isolation.

**Infrastructure failures we fixed (not "dumb AI"):**

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| Every httpx call failed | `httpx -l` treated the domain as a file path | build `httpx -u <domain>` in the wrapper |
| nmap SYN always failed | no raw sockets when unprivileged | default `-sT -Pn --unprivileged` in `command_builder` |
| Empty subfinder success | alias mismatch (`target` vs `domain`) | alias normalization; hard-fail on empty primary |
| Full `-p-` timeouts | 65535 ports × unprivileged × cap | scan-budget blocks full-range without `confirm_expensive` |
| Backend "hangs" after many timeouts | timed-out `docker exec` left running | kill-and-reap every timed-out process (`mcp_client._kill_and_reap`) |

---

## 8. Glossary

| Term | Meaning |
|------|---------|
| **Commander** | The LLM (OpenCode) — plans, chooses tools, narrates, decides when to stop |
| **Engagement** | Durable per-root-domain bucket (isolated Postgres storage) |
| **Run** | One MCP/OpenCode session under an engagement |
| **Finding** | A typed, evidence-graded fact parsed from tool output |
| **Engagement graph** | Typed asset nodes + named edges for pivots and cross-asset reasoning |
| **Evidence grade** | observed / inferred / unverified — clamps severity claims |
| **Finalize gate** | Blocks a COMPLETE report on weak, unproven claims |
| **`additional_args`** | Free-form CLI flags the LLM attaches to any tool |
| **Typed tool** | An MCP wrapper (`subfinder_scan`, `nmap_syn_scan`, …) with explicit params |
| **Escape hatch** | `platform_shell` (one allowlisted binary) / `platform_script` (invent anything) |

---

*Reflects the current OpenCode-primary recon+network build. For per-capability detail see [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md); for what is built vs planned see [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md).*
