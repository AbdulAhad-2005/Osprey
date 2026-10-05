# Architecture & Workflow

> **Audience:** Anyone evaluating how the platform works and *why* it is built this way — developers, operators, stakeholders.
> **Scope:** The full build. Recon, network, **web, vuln, exploit, and osint** phases are all implemented — their MCP tools (sqlmap, dalfox, nuclei, nikto, wpscan, metasploit, sslyze, the Playwright browser + session-aware repeater, …) are registered and driven by the conductor. See [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md).
> **Related:** [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) (operator) · [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md) (code map) · [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) (per-tool reference) · [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) (APIs)

---

## 1. The one-sentence idea

**The CLI is the harness; deterministic evidence-driven investigation is its baseline intelligence, and an LLM is an optional judgment layer.** You describe a target; the harness repeatedly senses typed state, selects one bounded opportunity, executes it through Kali, evaluates the evidence, and replans. A model may reorder current opportunities, interpret ambiguity, and add deliberate probes, but it does not replace the lifecycle or create a second control plane.

> **Motto:** We do not hardcode the engagement. We give the LLM trustworthy memory, safe execution primitives, transparent policy, and complete provenance so it can become an elite operator.

### One Harness, Explicit Capabilities

The CLI/external harness owns the root operator loop. The backend provides an
revisioned investigation state (`investigation_capabilities.py`), durable shared
state (`findings_store` + `engagement_graph`), bounded execution capabilities,
and explicit scoped-agent jobs. `GET /investigation/step` exposes ranked work;
`POST /investigation/step` validates one opaque decision and starts its durable
job. The backend never runs the root loop. A caller may spawn a bounded phase
agent deliberately, but there is no second backend Commander harness.

---

## 2. High-level architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  CLI / external harness + optional model judgment                 │
│  Owns sense → decide → act → evaluate → replan and stop           │
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
| **Investigation intelligence** | Evidence-ranked opportunities, prerequisites, coverage, replanning | CLI driver + `investigation_capabilities.py` |
| **Judgment layer (optional LLM)** | Reorder current opportunities, interpret ambiguity, propose deeper probes | CLI model driver or external MCP harness |

This split is the product's core bet: **the harness remains competent without a model; a model improves judgment without owning a parallel workflow.** Config owns execution defaults, the typed graph owns state, the investigation protocol owns lifecycle, and every driver uses the same bounded capabilities.

---

## 3. Harness and capability paths

The CLI or another external harness drives the platform. Both model-backed and
deterministic execution funnel through the same governed backend capabilities.

| Path | Entry | Status |
|------|-------|--------|
| **① CLI harness → embedded gateway → backend** | `cli/harness/` → `platform-mcp/server.py` embedding API → backend capabilities | **Primary product path.** One runtime owns session, drivers, workers, jobs, and events. |
| **② External MCP harness → platform-mcp → backend** | `platform-mcp/server.py` → `/api/v1/mcp/*` + `/api/v1/hybrid/*` | External clients consume the same capabilities and read-only readiness signals. |
| **③ Explicit scoped backend agent** | `/pipeline/spawn-agent` or `platform_spawn_agent` → `services/agent_runner.py` (a headless `cli.agent.loop.Runner` — the same loop as ①, no terminal) | Optional bounded capability for callers without native workers; never a root harness. |

Both paths funnel through the **same execution kernel** (`services/tool_execution.py`), so
governance, parsing, and memory behave identically regardless of driver.

---

## 4. From prompt to tool command

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
The surface an external harness sees. ~50 tools in three families:
- **Memory / notebook:** `platform_context`, `platform_think`, `platform_graph_link[_many]`, `platform_findings`, `platform_record_finding`, `platform_memory_search`, `platform_evidence_chain`, `platform_attempts`, `platform_priority`, `platform_finalize_check`, `platform_report_outline`, `platform_artifact`.
- **Execution lanes:** typed `*_scan`/`*_probe` (36 recon/network), `platform_exec`, `platform_shell`, `platform_script`, `platform_install`, `platform_job_start/poll/result`, `platform_fanout[_assets]`.
- Every stateful call accepts an explicit `engagement_id`. The ambient binding remains a convenience for one interactive session, but an explicit pin resolves the real target and owns a stable per-engagement run ID, so concurrent chats cannot borrow whichever target was bound most recently. Crash/respawn persistence is used only when the host supplies a unique `PENTEST_RUN_ID`; unidentified clients never share a global fallback state file.

### 5.2 Execution kernel (`services/tool_execution.py`)
One pipeline for every catalog tool (see §4). It is the single source of governance, validation, caching, target pacing, external-process admission, parsing, coverage, and audit — so "works in one path but breaks in another" cannot happen. `engagement_scheduler.py` supplies one queue per engagement at the actual MCP-call boundary; investigation capabilities, fanout, agents, direct calls, and background jobs cannot each create an independent concurrency pool and oversubscribe Kali. Waiting for a scheduler slot does not consume the tool's execution timeout.

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
The CLI owns session binding, the transcript, jobs, workers, events, cancellation,
and both investigation drivers. The deterministic driver selects from revisioned,
evidence-ranked opportunities. The LLM driver can choose a different current
opportunity but cannot invent asset identifiers or capability parameters; invalid
or unavailable model output falls back to deterministic selection. Switching
engagements or backend URLs invalidates model and investigation state so context
cannot leak across targets.

---

## 6. Design decisions (our way vs alternatives)

| Decision | Our choice | Why |
|----------|-----------|-----|
| Orchestration | **Harness-owned investigation protocol** | One lifecycle in LLM and no-LLM modes; every action is revisioned, visible, and bounded |
| Tool interface | **Structured tool calls + `additional_args`** | Same flag freedom as bash for scanning; none of the shell-injection risk |
| Skills/workflows | **Hints, not mandatory** | Assist like mature tools; don't force a YAML script |
| Execution paths | **One kernel** | One place for governance/parse/audit; no path drift |
| Runtime admission | **One per-engagement queue at the external-call boundary** | Bounds the combined load from every caller while preserving full tool access |
| Runtime | **Docker Kali sidecar** | Reproducible tool versions, isolation, raw-socket capability |
| Model | **Optional selection/analysis overlay** | Improves judgment while deterministic execution remains complete and provider-independent |
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
| **Harness** | The CLI or external client that owns sense → decide → act → evaluate → replan |
| **Model driver** | Optional judgment layer that chooses only from current typed opportunities |
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

*Reflects the harness-owned execution model: one external/CLI driver over
LLM-free readiness, deterministic capabilities, and optional scoped-agent jobs.
For per-capability detail see [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md).*
