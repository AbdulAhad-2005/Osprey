# Multi-Agent Handoff Guide — Commander, Summary, Recon & Network

> **Audience:** Friend taking over the **LLM / orchestration layer**  
> **Owner (execution/tools):** Original dev — Kali, MCP, command builder, governance, YAML matrices  
> **Working copy:** `llmwork/AI-Pentesting-Tool/`  
> **Date:** July 2026  
> **Related:** [`ARCHITECTURE_AND_WORKFLOW_EXPLAINED.md`](./ARCHITECTURE_AND_WORKFLOW_EXPLAINED.md) · [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md) · [`LLM_INTEGRATION.md`](./LLM_INTEGRATION.md)

---

## Table of Contents

1. [What You're Inheriting](#1-what-youre-inheriting)
2. [Target Architecture](#2-target-architecture)
3. [Agent Roles — Who Does What](#3-agent-roles--who-does-what)
4. [Current vs Target — Honest Gap](#4-current-vs-target--honest-gap)
5. [Implementation Plan (Phased)](#5-implementation-plan-phased)
6. [Files You Own vs Files You Touch](#6-files-you-own-vs-files-you-touch)
7. [Schemas to Add](#7-schemas-to-add)
8. [Orchestration Flow (Detailed)](#8-orchestration-flow-detailed)
9. [Skills — Folder Layout & Content Per Agent](#9-skills--folder-layout--content-per-agent)
10. [YAML Config — How Each Agent Uses It](#10-yaml-config--how-each-agent-uses-it)
11. [API & CLI Changes](#11-api--cli-changes)
12. [SSE Events for Multi-Agent UI](#12-sse-events-for-multi-agent-ui)
13. [Flexibility Rules (Do Not Break)](#13-flexibility-rules-do-not-break)
14. [Testing & Acceptance Criteria](#14-testing--acceptance-criteria)
15. [Demo Script After Split](#15-demo-script-after-split)
16. [FAQ / Pitfalls](#16-faq--pitfalls)

---

## 1. What You're Inheriting

Today there is **one LLM loop** (`AgentLoop` in `backend/src/pentest_platform/services/agent_loop.py`) that:

- Receives natural language + target from CLI (`cli/` → `POST /api/v1/agent/chat/stream`)
- Calls LiteLLM with **all** recon + network tools at once
- Runs tools via `tool_execution.py` → Kali Docker
- Parses stdout deterministically (`summary_agent.py` — **not** an LLM today)
- Appends YAML-based hints (`agent_assist.py` from `escalation_matrix.yaml` + `tech_dispatch.yaml`)
- Streams live progress over SSE

**Your job:** Split the **LLM brain** into:

| Agent | Type | Responsibility |
|-------|------|----------------|
| **Commander** | LLM (thin) | Plan phases, hand off, merge final report |
| **Recon agent** | LLM + tools | Subdomains, URLs, DNS, crawl, httpx |
| **Network agent** | LLM + tools | Ports, services, SMB, protocol enum |
| **Summary agent** | LLM (no tools) | Compress long tool output; phase briefs |

**You do NOT rebuild:** MCP servers, `command_builder.py`, governance, Docker, tool registry, parsers (unless Summary needs new fields).

---

## 2. Target Architecture

```
User prompt + target
        │
        ▼
┌───────────────────┐
│  COMMANDER (LLM)  │  reads: user goal, engagement, coverage gaps
│  No tools         │  outputs: phase plan OR "run recon" / "run network" / "done"
└─────────┬─────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌─────────┐ ┌──────────┐
│ RECON   │ │ NETWORK  │   each = PhaseAgent (fork of AgentLoop)
│ Agent   │ │ Agent    │   tools scoped by phase
│ + tools │ │ + tools  │
└────┬────┘ └────┬─────┘
     │           │
     │  after each heavy tool OR end of phase:
     ▼           ▼
┌───────────────────┐
│  SUMMARY (LLM)    │  compress stdout → PhaseBrief JSON + prose
│  No tools         │  feeds Commander + next phase agent
└─────────┬─────────┘
          ▼
┌───────────────────┐
│  COMMANDER        │  final user-facing report
└───────────────────┘

Shared (unchanged):
  findings_store · engagement_graph · tool_execution · parsers · YAML assist
```

**Design principle (non-negotiable):** YAML and skills **assist**; they do **not** auto-run tools. Phase agents keep `additional_args` freedom.

---

## 3. Agent Roles — Who Does What

### 3.1 Commander agent

| Aspect | Detail |
|--------|--------|
| **Runs** | Start of session; after each phase; at end |
| **Tools** | None (planning + synthesis only) |
| **Inputs** | User prompt, engagement RoE, `PhaseBrief` from recon/network, `findings_store.structured_summary_for_agent()`, `phase_reflection` coverage gaps |
| **Outputs** | `CommanderDecision`: which phase to run next, constraints for phase agent, final report markdown |
| **Skills** | `skills/commander/*.md` |
| **YAML** | Reads `tech_dispatch` + `phase_reflection` conceptually; does not execute workflows |

**Commander should NOT:** pick nmap flags or run subfinder. It delegates.

### 3.2 Recon agent

| Aspect | Detail |
|--------|--------|
| **Runs** | When Commander assigns `phase=recon` |
| **Tools** | `get_tools_for_llm_phase("recon")` only (~9 tools) |
| **Inputs** | Commander brief, target, `RESOLVED_IP`, full `load_skills_for_phase("recon")` |
| **Outputs** | `PhaseBrief` (via Summary), findings in store |
| **Skills** | `skills/recon/*.md` + shared escalation playbook |
| **YAML** | `recon_network_tools.yaml` tasks: subdomain, httpx, wayback, crawl, dns |
| **Must not run** | nmap, enum4linux, masscan, rustscan |

**Stop conditions:** Subdomain + live URL coverage OK for goal, or max turns, or Commander recall.

### 3.3 Network agent

| Aspect | Detail |
|--------|--------|
| **Runs** | After recon (default) or when Commander assigns `phase=network` |
| **Tools** | `get_tools_for_llm_phase("network")` only (~15 tools) |
| **Inputs** | Commander brief, **`HandoffPacket` from recon** (hosts, URLs, IPs), network skills |
| **Outputs** | `PhaseBrief`, port/service findings |
| **Skills** | `skills/network/*.md` |
| **YAML** | port_discovery, service_enumeration, smb escalations |
| **Must not run** | subfinder, amass (unless Commander re-opens recon) |

**Respect user constraints:** e.g. "no full port scan" → enforce in Commander brief + network system prompt.

### 3.4 Summary agent

| Aspect | Detail |
|--------|--------|
| **Runs** | After each tool with stdout > N chars; end of each phase; optional before Commander final |
| **Tools** | None |
| **Inputs** | Raw stdout/stderr, tool metadata, existing parsed findings |
| **Outputs** | `ToolSummary` (short) + updates `PhaseBrief` |
| **Skills** | `skills/summary/*.md` |
| **Today** | `summary_agent.py` = **regex parser only** — you add LLM layer **on top**, keep parser as ground truth |

**Summary must:** preserve IPs, ports, hostnames, errors verbatim in structured fields even if prose is compressed.

---

## 4. Current vs Target — Honest Gap

| Component | Today | After your work |
|-----------|-------|-----------------|
| `agent_loop.py` | Single loop, all tools | `PhaseAgent` + `CommanderOrchestrator` |
| `agent.py` endpoint | Calls one `AgentLoop.run()` | Calls orchestrator |
| `summary_agent.py` | Parser only | Parser + optional `summarize_with_llm()` |
| `skills_loader.py` | Loads recon/network | Add `load_skills_for_agent(role)` |
| `commander_context.py` | API packet only | Used by Commander LLM each turn |
| Chat agent | Loads `phase-overview.md` only | Each agent loads full phase skills |
| `phase` param | Label only | Enforces tool filter |
| Separate LLM configs | One `LLM_MODEL` | Optional `LLM_COMMANDER_MODEL`, etc. |

---

## 5. Implementation Plan (Phased)

### Phase 1 — Minimal split (MVP, ~2–3 days)

**Goal:** Recon agent → handoff → Network agent, no Commander LLM yet (hardcoded sequence).

1. Extract `PhaseAgent` from `AgentLoop`:
   - `tools = get_tools_for_llm_phase(phase)` not `get_agent_tools()`
   - `skills = load_skills_for_phase(phase)`
   - Phase-specific system prompt template
2. Add `build_handoff_packet(engagement_id, run_id)` in new `phase_handoff.py`
3. Add `run_full_pentest()` in `orchestrator.py`:
   ```python
   recon = await phase_agent.run(phase="recon", prompt=user_prompt, ...)
   handoff = build_handoff_packet(...)
   network = await phase_agent.run(phase="network", prompt=handoff.to_prompt(), ...)
   return merge_results(recon, network)
   ```
4. Wire `agent.py` `phase=full` to orchestrator
5. SSE: emit `phase_start`, `phase_done`

**Acceptance:** Same scanme run as today, but CLI shows `[RECON]` then `[NETWORK]` sections.

### Phase 2 — Summary LLM (~1–2 days)

1. Add `services/summary_llm.py`:
   - Input: tool stdout (truncated), parser output, tool_name
   - Output: `ToolSummary` JSON + 5–10 line prose
2. Call after each tool in `PhaseAgent` before appending to message history
3. Store summaries in `PhaseBrief` accumulator
4. End-of-phase: one LLM call → `PhaseBrief` for Commander/handoff

**Acceptance:** Long nmap output compressed; IPs/ports still in findings store correctly.

### Phase 3 — Commander LLM (~2–3 days)

1. Add `services/commander_agent.py`:
   - Reads user goal + coverage gaps
   - Decides: `run_recon` | `run_network` | `reopen_recon` | `finish`
2. Replace hardcoded sequence in orchestrator
3. Commander produces final markdown report from both `PhaseBrief`s

**Acceptance:** User prompt "recon only" skips network; "deep network on X" can skip recon if findings exist.

### Phase 4 — Polish

- Per-agent model env vars
- Token budgets per agent
- `/api/v1/agent/status` shows orchestration mode
- Unit tests for handoff packet

---

## 6. Files You Own vs Files You Touch

### You create (new)

```
backend/src/pentest_platform/
  services/
    orchestrator.py          # top-level run_full_pentest
    commander_agent.py       # Commander LLM
    phase_agent.py           # extracted from agent_loop (or refactor agent_loop)
    phase_handoff.py         # HandoffPacket builder
    summary_llm.py           # LLM summary layer
  schemas/
    agent_run.py             # CommanderDecision, PhaseBrief, HandoffPacket, ToolSummary
skills/
  commander/
    commander-overview.md
    planning-rules.md
  summary/
    summary-overview.md
    compression-rules.md
  recon/
    agent-system.md          # NEW — recon-specific system instructions
  network/
    agent-system.md          # NEW — network-specific system instructions
```

### You modify

| File | Change |
|------|--------|
| `api/v1/endpoints/agent.py` | Call `orchestrator` when `phase=full` |
| `services/agent_loop.py` | Refactor into `PhaseAgent` or deprecate |
| `services/skills_loader.py` | `load_skills_for_agent(role: str)` |
| `core/config.py` | Optional per-agent model settings |
| `cli/ui/display.py` | Render `phase_start`, `agent_role` events |
| `schemas/hybrid.py` | Import or extend new agent schemas |

### Do not break (coordinate if change needed)

| File | Owner concern |
|------|----------------|
| `tool_execution.py` | Execution contract |
| `command_builder.py` | CLI safety fixes |
| `mcp_client.py` | Docker exec |
| `config/*.yaml` | Matrix content — propose additions via PR |
| `mcp-servers/**` | Tool wrappers |
| `parsers/recon_network.py` | Ground-truth parsing |

---

## 7. Schemas to Add

Create `backend/src/pentest_platform/schemas/agent_run.py`:

```python
from pydantic import BaseModel, Field

class ToolSummary(BaseModel):
    tool_name: str
    success: bool
    command: str = ""
    key_facts: list[str] = Field(default_factory=list)  # "22/tcp open ssh"
    errors: list[str] = Field(default_factory=list)
    prose: str = ""  # LLM compression for phase agent context

class PhaseBrief(BaseModel):
    phase: str  # recon | network
    target: str
    resolved_ip: str | None = None
    tool_summaries: list[ToolSummary] = Field(default_factory=list)
    structured_findings: str = ""  # from findings_store
    coverage_completed: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    recommended_next: list[str] = Field(default_factory=list)
    prose_summary: str = ""  # end-of-phase LLM narrative

class HandoffPacket(BaseModel):
    """Recon → Network."""
    target: str
    resolved_ip: str | None = None
    subdomains: list[str] = Field(default_factory=list)
    live_urls: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    primary_hosts: list[str] = Field(default_factory=list)  # IPs/hostnames to scan
    user_constraints: list[str] = Field(default_factory=list)  # e.g. "no full port scan"
    recon_brief: PhaseBrief | None = None

    def to_prompt(self) -> str:
        """Inject as first user message for network agent."""
        ...

class CommanderDecision(BaseModel):
    action: str  # run_recon | run_network | reopen_recon | finish
    reasoning: str = ""
    constraints: list[str] = Field(default_factory=list)
    user_message: str = ""  # optional mid-run update
```

**Handoff builder** (`phase_handoff.py`) should read from `findings_store` + `engagement_graph`, not from LLM prose alone.

---

## 8. Orchestration Flow (Detailed)

### 8.1 Full run (`phase=full`)

```
1. orchestrator.run_full(prompt, engagement_id, run_id)
2. commander.plan(prompt) → CommanderDecision(action=run_recon)
3. phase_agent.run(phase=recon, tools=recon only, skills=full recon)
   loop:
     llm → tool → execute_tool_request() → parser → findings
     if len(stdout) > 4000: summary_llm.compress() → ToolSummary
     agent_assist hints appended (unchanged)
4. phase_brief = summary_llm.summarize_phase(recon)
5. handoff = build_handoff_packet(recon_brief)
6. commander.plan(handoff) → CommanderDecision(action=run_network)
7. phase_agent.run(phase=network, initial_context=handoff)
8. network_brief = summary_llm.summarize_phase(network)
9. final = commander.final_report(recon_brief, network_brief)
10. SSE done
```

### 8.2 Single phase (`phase=recon` or `phase=network`)

Skip Commander sequence; run one `PhaseAgent` only (current behavior, but tool-scoped).

### 8.3 What stays the same inside each tool call

```
PhaseAgent._execute_tool()
  → ToolExecutionRequest(use_recovery=False)  # keep off on agent path
  → tool_execution.execute_tool_request()
  → enrich_tool_result_for_agent()  # agent_assist + YAML hints
  → (NEW) optional summary_llm for huge stdout
  → append to messages
```

---

## 9. Skills — Folder Layout & Content Per Agent

### 9.1 Directory layout (target)

```
skills/
├── commander/
│   ├── commander-overview.md      # NEW — role & boundaries
│   └── planning-rules.md          # NEW — when to run which phase
├── summary/
│   ├── summary-overview.md        # NEW — what to preserve when compressing
│   └── compression-rules.md       # NEW — anti-hallucination rules
├── recon/
│   ├── agent-system.md            # NEW — recon agent system instructions
│   ├── phase-overview.md          # EXISTS
│   ├── subdomain-enumeration.md   # EXISTS
│   ├── live-host-probing.md       # EXISTS
│   ├── historical-url-discovery.md
│   ├── web-crawling.md
│   ├── dns-intelligence.md
│   └── waf-pivot.md               # NEW — recommended
├── network/
│   ├── agent-system.md            # NEW
│   ├── phase-overview.md
│   ├── port-scan-strategy.md
│   ├── service-enumeration.md
│   └── smb-enumeration.md
└── shared/
    ├── escalation-playbook.md
    ├── finding-confidence.md
    ├── governance-rules.md
    ├── sister-domain-discovery.md
    └── tool-selection-ux.md
```

### 9.2 `skills_loader.py` changes

```python
def load_skills_for_agent(role: str, phase: str | None = None) -> str:
    if role == "commander":
        return _load_dir("commander")
    if role == "summary":
        return _load_dir("summary")
    if role in ("recon", "network"):
        return load_skills_for_phase(role) + "\n\n" + _read_skill(f"{role}/agent-system.md")
    ...
```

---

### 9.3 Commander skills — what to write

#### `skills/commander/commander-overview.md`

```markdown
# Commander Agent

You orchestrate recon and network phases. You do **not** execute tools.

## Your outputs
- Decide: run recon, run network, reopen recon, or finish
- Pass **constraints** verbatim from the user (e.g. "no full port scan", "passive only")
- Synthesize final report from PhaseBriefs — do not invent findings

## Inputs you trust (in order)
1. Structured findings from the platform (findings_store)
2. PhaseBrief prose from Summary agent
3. Coverage gaps from phase_reflection
4. User's original prompt

## You must not
- Hallucinate open ports or subdomains
- Override governance / out-of-scope rules
- Force a tool name with specific flags (delegate to phase agents)
```

#### `skills/commander/planning-rules.md`

```markdown
# Planning Rules

## Default sequence
1. Recon on root target (unless user says "network only" and handoff exists)
2. Network on hosts/IPs discovered in recon
3. Finish with executive summary + recommended next steps

## Reopen recon when
- Network finds new hostname not in recon brief
- User asks for deeper subdomain enum mid-run

## Skip network when
- User explicitly asks recon-only
- No live hosts and no IPs to scan after recon

## Constraints to forward
Always copy user limits into phase agent context:
- "no full port scan" → network must not use -p- or 1-65535
- "passive only" → recon avoids intrusive tools
```

---

### 9.4 Summary agent skills — what to write

#### `skills/summary/summary-overview.md`

```markdown
# Summary Agent

Compress tool output for other LLM agents. You have **no tools**.

## Preserve exactly (never drop)
- IP addresses, hostnames, ports, URLs
- Exit codes, timeout messages, explicit errors
- WAF/block indicators (403, Cloudflare, etc.)

## You may compress
- Repetitive nmap noise, progress bars, duplicate lines
- Verbose banners (keep service name + version)

## Output format
1. `key_facts`: bullet list of atomic facts
2. `errors`: list of failures
3. `prose`: 5–10 sentences max for phase agent context

## Ground truth
Parser output from the platform overrides your reading if they conflict.
```

#### `skills/summary/compression-rules.md`

```markdown
# Compression Rules

- If stdout > 4000 chars, summarize; attach full text only in storage not in LLM context
- For nmap: list open ports as `port/proto service version`
- For subfinder/amass: count + unique hostnames (dedupe)
- For httpx: URL, status code, title, tech if present
- Never suggest next tools — that is phase agent / YAML assist job
```

---

### 9.5 Recon agent — `skills/recon/agent-system.md` (NEW)

```markdown
# Recon Phase Agent

You are the **recon specialist**. You run only recon-phase tools.

## Scope
- Subdomain enumeration, live HTTP probing, historical URLs, light crawl, DNS intel
- **Do not** run nmap, masscan, rustscan, enum4linux, smbmap

## Tool freedom
- Use `additional_args` for any valid CLI flags (subfinder -all, httpx -td, etc.)
- Skills and OPTIONAL SUGGESTIONS are hints — not orders

## Workflow (suggested)
1. Passive subdomain enum on root domain
2. httpx on discovered hosts
3. Historical URLs / light crawl on interesting live URLs
4. DNS intel if nameservers unclear

## WAF / blocked root
If httpx shows 403 on `/`, try path/header pivots from skills/live-host-probing.md
and OPTIONAL SUGGESTIONS — then document what worked.

## Stop when
- User goal for recon is met, or
- Commander recalls you, or
- max turns reached — emit concise status of what was found
```

#### Expand `skills/recon/live-host-probing.md` (add section)

```markdown
## WAF pivot families (examples — not exhaustive)
- Path: `/index.php/`, `/api/`, trailing dot, case variants
- Headers: `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`
- Method: GET vs POST on same path
- Historical: waybackurls may hit unprotected old endpoints
Use httpx `additional_args` for any of these. Combine with graph pivot (siblings on same IP).
```

#### Add `skills/recon/waf-pivot.md` (optional dedicated file)

Short cheat sheet of signal → try → document result. Link from live-host-probing.

---

### 9.6 Network agent — `skills/network/agent-system.md` (NEW)

```markdown
# Network Phase Agent

You are the **network specialist**. You run only network-phase tools.

## Scope
- Port discovery, service/version scan, SMB/NetBIOS when ports open
- **Do not** rerun subfinder/amass unless recon was empty and Commander says so

## Inputs
Read the HANDOFF PACKET first:
- `primary_hosts` / `resolved_ip` — scan these
- `user_constraints` — e.g. NO `-p-` or `1-65535`
- Recon brief — do not rescan blindly

## Port strategy
- Prefer `--top-ports 1000` or known open ports from recon
- Use `-Pn` when host blocks ping
- Container is unprivileged: prefer `-sT` / `--unprivileged` over raw SYN

## Protocol follow-up
- 445/139 open → SMB enum tools
- Linux target with no SMB → skip after one failure (read HINT)
- 80/443 only → service scan + scripts, not full UDP unless asked

## Stop when
- Services enumerated for user goal, or max turns, or Commander finish
```

#### Expand `skills/network/port-scan-strategy.md`

Add explicit section:

```markdown
## User constraint: no full port scan
Never use `-p-`, `1-65535`, or rustscan `--ulimit` wide sweeps when handoff says so.
Use: `--top-ports 1000`, or explicit list from recon (80,443,22,...).
```

---

### 9.7 Shared skills (all agents read selectively)

| File | Commander | Summary | Recon | Network |
|------|-----------|---------|-------|---------|
| `finding-confidence.md` | ✓ | ✓ | ✓ | ✓ |
| `governance-rules.md` | ✓ | — | ✓ | ✓ |
| `escalation-playbook.md` | ✓ | — | ✓ | ✓ |
| `sister-domain-discovery.md` | — | — | ✓ | — |

---

## 10. YAML Config — How Each Agent Uses It

| YAML file | Commander | Recon agent | Network agent | Summary |
|-----------|-----------|-------------|---------------|---------|
| `recon_network_tools.yaml` | Catalog awareness | Tool schemas | Tool schemas | — |
| `escalation_matrix.yaml` | Playbook context | Via `agent_assist` after tools | Via `agent_assist` | — |
| `tech_dispatch.yaml` | Planning gaps | Via `agent_assist` | Via `agent_assist` | — |
| `workflows.yaml` | May suggest as optional | Not auto-run | Not auto-run | — |

**Do not** wire `workflows.yaml` into phase agents as mandatory — keep for `/hybrid/workflows/.../run` API only unless Commander explicitly chooses one.

### YAML additions welcome (coordinate)

- More `live_host_probing` WAF escalations in `escalation_matrix.yaml`
- `service_enumeration` entries for `--top-ports` when user constraint present (signal: `user_no_full_scan`)

---

## 11. API & CLI Changes

### Endpoints

| Endpoint | Change |
|----------|--------|
| `POST /api/v1/agent/chat` | `phase=full` → orchestrator |
| `POST /api/v1/agent/chat/stream` | New events: `phase_start`, `phase_done`, `agent_role` |
| `GET /api/v1/agent/status` | Add `orchestration: multi-agent`, agent model names |
| `GET /api/v1/hybrid/context/{phase}` | Unchanged — Commander can call for planning |

### Request body (optional extensions)

```json
{
  "prompt": "...",
  "phase": "full",
  "orchestration": "multi-agent",
  "skip_commander": false,
  "max_turns_recon": 20,
  "max_turns_network": 20
}
```

### CLI

`cli/ui/display.py` — prefix lines:

```
[Commander] Planning: run recon first
[Recon] ▶ subfinder_scan(...)
[Summary] Compressed nmap output (12k → 800 chars)
[Network] ▶ nmap_service_scan(...)
[Commander] Final report
```

---

## 12. SSE Events for Multi-Agent UI

Extend `agent_loop` / orchestrator `emit()`:

| Event | Payload |
|-------|---------|
| `agent_role` | `{ "role": "commander" \| "recon" \| "network" \| "summary" }` |
| `phase_start` | `{ "phase": "recon", "run_id": "..." }` |
| `phase_done` | `{ "phase": "recon", "brief": {...} }` |
| `handoff` | `{ "packet": HandoffPacket }` (optional, debug) |
| `tool_start` / `tool_end` | Add `"phase": "recon"` field |
| `done` | Include `phases: [{phase, tool_calls, duration}]` |

---

## 13. Flexibility Rules (Do Not Break)

These are product requirements from the original dev:

1. **LLM chooses tool order** — Commander plans phases, not individual nmap flags
2. **`additional_args` is open** — any valid CLI flags except shell metacharacters
3. **YAML/skills are OPTIONAL SUGGESTIONS** — never auto-execute escalations
4. **`use_recovery=False`** on agent tool path — no HexStrike auto-retry spam
5. **Findings store is ground truth** — Summary/Commander must not contradict parsed findings
6. **User constraints in natural language** must flow: User → Commander → Handoff → Network agent

---

## 14. Testing & Acceptance Criteria

### Unit tests

- `build_handoff_packet()` with mock findings
- `PhaseAgent` only exposes recon tools when `phase=recon`
- `HandoffPacket.to_prompt()` includes constraints

### Integration (scanme.nmap.org)

| Test | Pass criteria |
|------|----------------|
| Full run | Recon tools run before nmap; CLI shows two phases |
| "no full port scan" | No `-p-` / `1-65535` in commands |
| Recon-only `phase=recon` | No nmap in tool log |
| Summary | nmap stdout in LLM context < 2k chars; ports still in findings |
| Commander final | Report lists 22, 80, http; no invented CVEs |

### Regression

- `docker compose up` healthy
- `/status` shows models + tool counts
- Gemini message history pruning still works (`_prune_message_history`)

---

## 15. Demo Script After Split

```powershell
cd llmwork\AI-Pentesting-Tool
docker compose up -d --force-recreate backend
cd cli
python -m cli
```

```
/status
Complete recon and network analysis on scanme.nmap.org.
Map maximum attack surface but do NOT run a full port scan.
```

**Show manager:**

1. `[Commander]` planning line  
2. `[Recon]` subfinder → httpx → wayback  
3. `[Handoff]` primary host `45.33.32.156`  
4. `[Network]` nmap top ports / targeted scan  
5. `[Commander]` final report  
6. Swagger: `GET /api/v1/findings` — structured data  

---

## 16. FAQ / Pitfalls

**Q: Should Commander call tools?**  
A: No. Thin planner + reporter only.

**Q: Replace `summary_agent.py` parser?**  
A: No. LLM summarizes; parser still writes findings.

**Q: Separate API keys per agent?**  
A: Optional later (`LLM_COMMANDER_MODEL`, etc.). MVP can share one model.

**Q: Shannon has 10+ agents — do we need that?**  
A: Not for recon+network MVP. Four roles are enough.

**Q: `phase=full` still one HTTP request?**  
A: Yes — orchestrator runs phases inside one stream.

**Q: What if recon finds nothing?**  
A: Commander should still allow network on root domain/IP from user prompt.

**Pitfall:** Network agent reruns subfinder — fix with handoff + system prompt + tool filter.

**Pitfall:** Summary drops ports — require `key_facts` from parser merge.

**Pitfall:** Token explosion — Summary after each large tool; prune per-phase message history.

---

## Quick Reference — Key Existing Files

| Path | Purpose |
|------|---------|
| `services/agent_loop.py` | **Refactor this** — current monolithic agent |
| `services/llm_service.py` | LiteLLM wrapper |
| `services/tool_discovery.py` | `get_tools_for_llm_phase()` |
| `services/tool_execution.py` | Execute in Kali |
| `services/agent_assist.py` | YAML hints after tools |
| `services/commander_context.py` | Rich context packet (use for Commander) |
| `services/phase_reflection.py` | Coverage gaps |
| `services/skills_loader.py` | Load markdown skills |
| `config/recon_network_tools.yaml` | Tool catalog |
| `config/escalation_matrix.yaml` | Failure pivots |
| `config/tech_dispatch.yaml` | Finding-driven suggestions |
| `api/v1/endpoints/agent.py` | Chat + SSE entry |

---

## Contact / Handoff Checklist

- [ ] Read `ARCHITECTURE_AND_WORKFLOW_EXPLAINED.md`
- [ ] Run one successful `scanme.nmap.org` on current single-agent build
- [ ] Implement Phase 1 (hardcoded recon → network split)
- [ ] Add `skills/*/agent-system.md` + commander/summary skills
- [ ] Implement Summary LLM (Phase 2)
- [ ] Implement Commander LLM (Phase 3)
- [ ] Update CLI for phase labels
- [ ] Demo with manager script (Section 15)

**Questions on execution layer / YAML content:** original dev  
**Questions on LiteLLM / agent prompts / orchestration:** you (friend)

---

*End of handoff guide.*
