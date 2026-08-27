# Architecture & Workflow

> **Audience:** Anyone evaluating how the platform works and *why* it is built this way — developers, operators, stakeholders.
> **Scope:** The full build. Recon, network, **web, vuln, exploit, and osint** phases are all implemented — their MCP tools (sqlmap, dalfox, nuclei, nikto, wpscan, metasploit, sslyze, the Playwright browser + session-aware repeater, …) are registered and driven by the conductor. See [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md).
> **Related:** [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) (operator) · [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md) (code map) · [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) (per-tool reference) · [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) (APIs)

---

## 1. The one-sentence idea

**An external LLM (OpenCode) is the brain; the platform is a lab + referee + shared notebook.** You describe a target in plain English; the LLM chooses security tools from a governed catalog, runs them in Kali via MCP, reads the full output, adapts, writes typed findings into a durable engagement graph, and reports back — while YAML config and markdown skills *assist* it, not *script* it.

> **Motto:** We do not hardcode the engagement. We give the LLM trustworthy memory, safe execution primitives, transparent policy, and complete provenance so it can become an elite operator.

### One Conductor, Two Executors

The brain is pluggable. The **conductor** (`phase_supervisor.py` + `sufficiency.py`) is LLM-free
shared state — phase sequencing (recon first; vuln/exploit unlock on evidence thresholds),
loop-back on new assets, the tool catalog, per-phase skills, and the shared blackboard
(`findings_store` + `engagement_graph`). It decides *what/when*, never *how*, and never calls an
LLM. Two interchangeable executors consume that one conductor:

- **Executor A — an external harness** (OpenCode / Claude Code / any MCP client) using its own
  LLM and subagents, reaching the conductor over the `pentest-platform` MCP tools. No key needed
  — the affordable default.
- **Executor B — the built-in Commander** (`services/phase_agent.py` `phase="commander"`, entered
  via `POST /api/v1/agent/chat[/stream]`). A self-hosted conversational brain running whatever
  LiteLLM key the user configures (Claude / DeepSeek / GPT / Groq / **local Ollama**). It owns the
  conductor as a background job: `launch_pipeline` runs recon→vuln→exploit fire-and-forget while
  the Commander stays conversational, `check_readiness` reports progress, `spawn_agent` steers,
  `stop_pipeline` halts. Target binding is **lazy and implicit** — naming a target in chat
  get-or-creates its engagement; there is no `set_target` ceremony.

Both executors read skills the same way (description-indexed, surfaced at the active phase, pulled
on demand) and write to the same evidence graph, so they cannot diverge. New intelligence goes
into the LLM-free conductor + skills, never into a per-executor service.

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
      b. param_validator             (blocks shell metacharacters only)
      c. scan_budget                 (blocks full-range -p- / 1-65535 w/o confirm)
      d. exec cache                  (same engagement+tool+params within ~1h → cache_hit)
      e. command_builder             (loads mcp-servers/recon/tools/httpx_probe.py)
      f. rate_governor               (paces calls per target; skips banned targets — see §6)
      g. mcp_client → docker exec ai-pentest-kali → httpx -u scanme.nmap.org …
         (ban-fingerprint scan on stdout → cooldown + one OBSERVATION finding)
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

> **Durability:** findings, the graph, **job history** (`scan_runs`), and the **context delta** (`context_snapshots`) all survive a backend restart. A job's *live execution* is an asyncio task that cannot survive a restart by nature, so on startup any run still marked `queued`/`running` is reconciled to a terminal `failed` state (see `scan_run_store.reconcile_orphaned_runs`) rather than showing as a phantom forever-running job. The rate governor's **ban cooldowns** are also durable (`target_bans`, rehydrated at startup) — a cooldown can run ~10 min, so losing it to a restart would immediately re-hammer a target that just blocked us. Its sliding call **window** stays in-process (touched on every call — a per-call DB round-trip would tax every scan, and a 60s window is meaningless after a restart), and in-flight parallel-agent **claims** stay in-process by design: a claim means "running right now", so after a restart (when nothing is in flight) an empty map is exactly correct and a persisted claim would be a phantom.

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

**Governance note (accurate current state):** there is **no scope-based governance gate** — the standalone governance engine was removed, and `tool_execution` does not block tools by matching targets against a declared scope. This is deliberate: unrestricted scanning keeps the pentest smooth (real findings often live on the less-guarded sister/sub domains, not the hardened apex). Scope discipline is operator guidance in `AGENTS.md`, not a backend block. What *does* still gate execution: **RulesOfEngagement on exploitation-tier tools** — a `GATED` tool (exploit/creds/destructive) is refused unless the engagement's `allow_exploitation` (and, for destructive calls, `destructive_actions_allowed`) is set. And the one active pacing layer, the **rate governor** (`rate_governor.py`): a per-target sliding-window pacer plus WAF/rate-limit ban detector that *delays* calls and reports bans — it never refuses one. On a clean tool failure the kernel also auto-runs the top fallback (`escalation_matrix.yaml` → `auto_fallback`), and auto-drops to a stealth intensity profile against a target the governor has cooled down. See §5.7.

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

*Reflects the two-executor build: an external MCP harness (Executor A) and the built-in Commander (Executor B), over one LLM-free conductor spanning recon/network/web/vuln/exploit/osint. For per-capability detail see [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md).*
