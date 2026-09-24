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
  LLM and subagents, reaching the conductor over the `osprey` MCP tools. No key needed
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
│  platform-mcp/server.py  (FastMCP gateway)                        │
│  Explicit engagement pins · typed offensive tools · notebook ·    │
│  exec / shell / script / durable jobs / fanout                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │ HTTP → localhost:9000
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  backend (FastAPI :9000)                                          │
│  ONE execution kernel: govern · validate · scan-budget · cache ·  │
│  pace · schedule · execute · parse → findings · ingest → graph ·  │
│  coverage · recovery hints · durable audit                         │
└───────────────┬──────────────────────────────────┬───────────────┘
                │ docker exec                        │ SQL
                ▼                                    ▼
┌───────────────────────────┐        ┌──────────────────────────────┐
│  osprey-kali              │        │  PostgreSQL / SQLite         │
│  mcp-servers/* + binaries │        │  engagements · runs ·        │
│  (nmap, subfinder, httpx…)│        │  findings · asset_nodes ·    │
│                           │        │  graph · jobs · audit         │
└───────────────────────────┘        └──────────────────────────────┘
```

### Four conceptual roles

| Role | Responsibility | Where it lives |
|------|----------------|----------------|
| **Lab** | Tools, allowlisted shell, custom scripts, jobs, fanout, artifacts | `mcp-servers/`, `kali-tools/`, exec/shell/script services |
| **Shared notebook** | Executions, findings, engagement graph, evidence, decisions | `findings_store`, `engagement_graph`, Postgres |
| **Referee** | Scope/governance, scan budget, evidence law, report integrity | `governance`, `scan_budget`, `schemas/finding.py`, `finalize_*` |
| **Brain (LLM)** | Which tool, what flags, relation meaning, confirmation, stopping | OpenCode + `AGENTS.md` + `skills/` |

This split is the product's core bet: **config owns safety and defaults; cognition belongs to the LLM.** It was synthesized from analyzing Shannon (durable phases + validation rigor), the Shannon OpenCode plugin (LLM-as-orchestrator + Docker tools), Dark-Moon (reactive chaining + `additional_args` freedom + MCP gatekeeper), and HexStrike (broad Kali tool surface + command recipes) — keeping the best of each.

---

## 3. The two executor paths

There are two ways an LLM can drive the platform. Both consume the same LLM-free
conductor and funnel through the same execution kernel, so they cannot diverge.

| Path | Entry | Status |
|------|-------|--------|
| **① External MCP harness → platform-mcp → backend** | `platform-mcp/server.py` → `/api/v1/mcp/*` + `/api/v1/hybrid/*` | **Default.** The brain is external (OpenCode / Claude Desktop / any MCP client); no LLM key needed on the platform. |
| **② Built-in Commander + CLI** | `POST /api/v1/agent/chat[/stream]` → `services/phase_agent.py` (`phase="commander"`) + `cli/` | **Opt-in.** Off by default (`enable_builtin_agent=false`); set it true to run a self-hosted conversational brain on your own LiteLLM key. |

Both paths funnel through the **same execution kernel** (`services/tool_execution.py`), so
governance, parsing, and memory behave identically regardless of driver.

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
      f. rate_governor               (atomically paces calls per target — see §6)
      g. engagement_scheduler        (one shared per-engagement execution queue)
      h. mcp_client → docker exec osprey-kali → httpx -u scanme.nmap.org …
         (ban-fingerprint scan on stdout → cooldown + one OBSERVATION finding)
      i. summarize_execution         (parsers → Finding objects) + apply_ingest_rules (YAML)
      j. findings_store + engagement_graph ingest → database
      k. tool coverage · artifacts · recovery hints · durable audit entry
5. Response → OpenCode (stdout + finding_titles + soft next-hints)
6. Next turn: platform_context shows updated gaps → LLM decides the next move
```

**Critical design choice:** the LLM never sends raw shell. It sends **structured tool calls** (or an allowlisted single-binary `platform_shell`, or a sandboxed `platform_script`). The platform builds the CLI string. This gives full flag flexibility (any flags via `additional_args`) without arbitrary command injection.

---

## 5. The layers — what each does and why

### 5.1 platform-mcp gateway (`platform-mcp/server.py`)
The surface an external harness sees. Its tools fall into three families:
- **Memory / notebook:** `platform_context`, `platform_think`, `platform_graph_link[_many]`, `platform_findings`, `platform_record_finding`, `platform_memory_search`, `platform_evidence_chain`, `platform_attempts`, `platform_thinking`, `platform_finalize_check`, `platform_report_outline`, `platform_artifact`.
- **Execution lanes:** typed `*_scan`/`*_probe` (36 recon/network), `platform_exec`, `platform_shell`, `platform_script`, `platform_install`, `platform_job_start/poll/result`, `platform_fanout[_assets]`.
- Every stateful call accepts an explicit `engagement_id`. The ambient binding remains a convenience for one interactive session, but an explicit pin resolves the real target and owns a stable per-engagement run ID, so concurrent chats cannot borrow whichever target was bound most recently. Crash/respawn persistence is used only when the host supplies a unique `PENTEST_RUN_ID`; unidentified clients never share a global fallback state file.

### 5.2 Execution kernel (`services/tool_execution.py`)
One pipeline for every catalog tool (see §4). It is the single source of governance, validation, caching, target pacing, external-process admission, parsing, coverage, and audit — so "works in one path but breaks in another" cannot happen. `engagement_scheduler.py` supplies one queue per engagement at the actual MCP-call boundary; expansion, fanout, agents, direct calls, and background jobs cannot each create an independent concurrency pool and oversubscribe Kali. Waiting for a scheduler slot does not consume the tool's execution timeout.

### 5.3 Command builder (`command_builder.py` + `mcp-servers/*/tools/*.py`)
Per-tool `build_command()` functions harvested from HexStrike and hardened. The MCP tool module is the single source of truth for the actual CLI shape; the backend builder adds container-aware defaults (e.g. nmap falls back to `-sT -Pn --unprivileged` when raw sockets are unavailable).

### 5.4 Memory: findings + engagement graph (`findings_store.py`, `engagement_graph.py`)
Parsed outputs become typed `Finding` rows; the graph links assets (host → port → service, subdomain → domain, sibling-on-same-IP). All **durable in Postgres**, scoped per engagement so two targets never collide. This is the "shared notebook" that lets a long engagement survive context limits.

> **Durability:** findings, the graph, **job history** (`scan_runs`, including the original request, command preview, progress heartbeat, lineage, and final result), the **execution audit** (`audit_entries`), and the **context delta** (`context_snapshots`) survive a backend restart. A job's *live execution* is an asyncio task that cannot survive a restart by nature, so startup reconciles any durable `queued`/`running` row to a terminal `failed` state instead of showing a phantom forever-running job. Ban cooldowns are also durable (`target_bans`, rehydrated at startup). The short sliding call window, live event stream, scheduler leases, and in-flight claims remain process-local because persisting them would add hot-path writes or revive state that is no longer live.

> **Schema lifecycle:** SQLite and PostgreSQL both follow the same Alembic migration chain. Startup reports `503 not_ready` if migration fails instead of claiming healthy. Legacy SQLite databases that were created directly from ORM metadata are inspected, conservatively stamped at the newest schema they actually satisfy, and upgraded without discarding existing data.

> **Deletion lifecycle:** deleting an engagement first cancels and awaits all owned jobs, then removes every durable child table, then clears process-local context, cache, pacing, scheduler, stdout, audit-fallback, and event state. This prevents a cancelled task from writing the deleted engagement back into existence.

Health responses include a machine-readable API contract version and additive capability identifiers. Clients can distinguish a genuinely unavailable feature from a backend/CLI version mismatch without guessing from a failed endpoint.

### 5.5 Evidence discipline — advisory, not a clamp (`schemas/finding.py`)
Every finding carries a `confidence` (`confirmed` / `likely` / `hypothesis`) and a `claim_severity` — two independent signals, not one derived from the other. There is no platform-side clamp: the parser/agent assigns both honestly, per `skills/vuln/verification-and-severity.md` (detection-only → confidence LIKELY, severity capped at HIGH; actual proof of exploitation → CONFIRMED, may reach CRITICAL). `platform_finalize_check`/`platform_report_outline` surface phase readiness and a Confirmed/Likely/Hypotheses breakdown, purely informational — nothing blocks a report from being written; the driver decides what's ready.

Permissive parsing is intentional. Partial stdout from a failed or timed-out command may still contain real target observations and is retained with `partial_failed_output` provenance. Failed-process stderr/error text is diagnostic rather than target evidence: it remains in artifacts, recovery analysis, and the audit trail, but is not promoted into findings by itself.

### 5.6 Guidance: skills + config (`skills/`, `config/`)
Markdown skills (methodology) and YAML config (tool catalog, escalation matrix, tech dispatch, ingest rules, thinking-model scoring, playbooks) **advise** the LLM. Everything here is soft except the hard safety rails (scan budget, Rules-of-Engagement gating on exploit/destructive tools, shell-metacharacter ban on the typed-tool path).

### 5.7 Kali execution (`mcp_client.py` + `kali-tools/`)
Tools run inside the `osprey-kali` container (NET_RAW/NET_ADMIN for SYN scans). The backend mounts the docker socket and `docker exec`s into Kali. Timed-out processes are killed and reaped so long scans can't leak process slots.

### 5.8 CLI harness (`cli/`)
The CLI owns a persistent local `Runner` per selected engagement. Switching engagements or backend URLs invalidates the runner so conversation/system context cannot leak across targets. Fresh runners and spawned workers always request a full baseline context; later refreshes may use deltas. Markdown-defined agents and commands under `.osprey/` or `~/.osprey/` add prompt overlays and reusable flows without code changes. Tool filtering is opt-in and only narrows capability when the operator explicitly selects such an agent; the default retains the complete catalog.

---

## 6. Design decisions (our way vs alternatives)

| Decision | Our choice | Why |
|----------|-----------|-----|
| Orchestration | **LLM orchestrator** (OpenCode) | Adapts to prompt, failures, target shape — vs a rigid fixed pipeline |
| Tool interface | **Structured tool calls + `additional_args`** | Same flag freedom as bash for scanning; none of the shell-injection risk |
| Skills/workflows | **Hints, not mandatory** | Assist like mature tools; don't force a YAML script |
| Execution paths | **One kernel** | One place for governance/parse/audit; no path drift |
| Runtime admission | **One per-engagement queue at the external-call boundary** | Bounds the combined load from every caller while preserving full tool access |
| Runtime | **Docker Kali sidecar** | Reproducible tool versions, isolation, raw-socket capability |
| Model | **LiteLLM-agnostic** (built-in Commander) / any MCP client (external harness) | Swap providers without rewriting the platform |
| Memory | **Durable typed graph + honest confidence** | The differentiator none of the reference tools fully have |
| Database evolution | **Alembic for SQLite and PostgreSQL** | One tested upgrade path; no create-all schema drift |

**Governance note (accurate current state):** there is **no scope-based governance gate** — the standalone governance engine was removed, and `tool_execution` does not block tools by matching targets against a declared scope. This is deliberate: unrestricted scanning keeps the pentest smooth (real findings often live on the less-guarded sister/sub domains, not the hardened apex). Scope discipline is operator guidance in `AGENTS.md`, not a backend block. What *does* still gate execution: **RulesOfEngagement on exploitation-tier tools** — a `GATED` tool (exploit/creds/destructive) is refused unless the engagement's `allow_exploitation` (and, for destructive calls, `destructive_actions_allowed`) is set. And the one active pacing layer, the **rate governor** (`rate_governor.py`): a per-target sliding-window pacer plus WAF/rate-limit ban detector that *delays* calls and reports bans — it never refuses one. On a clean tool failure the kernel also auto-runs the top fallback (`escalation_matrix.yaml` → `auto_fallback`), and auto-drops to a stealth intensity profile against a target the governor has cooled down. See §5.7.

---

## 7. What worked, what failed, what we fixed (recon/network build)

**Worked as designed:** autonomous tool choice and ordering; adaptation after a timeout (full `-p-` → targeted port list); durable memory across turns; findings with honest confidence; honest finalize gating; multi-target isolation.

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
| **Finding** | A typed fact parsed from tool output, with an honest confidence and severity |
| **Engagement graph** | Typed asset nodes + named edges for pivots and cross-asset reasoning |
| **Confidence** | confirmed / likely / hypothesis — assigned independently from severity, never clamps it |
| **Finalize check** | Advisory readiness signal for weak or unproven claims; it does not block reporting |
| **`additional_args`** | Free-form CLI flags the LLM attaches to any tool |
| **Typed tool** | An MCP wrapper (`subfinder_scan`, `nmap_syn_scan`, …) with explicit params |
| **Escape hatch** | `platform_shell` (one allowlisted binary) / `platform_script` (invent anything) |

---

*Reflects the two-executor build: an external MCP harness (Executor A) and the built-in Commander (Executor B), over one LLM-free conductor spanning recon/network/web/vuln/exploit/osint. For per-capability detail see [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md).*
