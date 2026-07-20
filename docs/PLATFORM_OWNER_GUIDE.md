# Platform Owner Guide — Your Work, Merge Plan & Strategy

> **You:** Execution layer — tools, YAML, parsers, Docker, handoff contract, platform quality  
> **Friend:** Multi-agent LLM layer — see [`MULTI_AGENT_HANDOFF_GUIDE.md`](./MULTI_AGENT_HANDOFF_GUIDE.md)  
> **Repo:** `llmwork/AI-Pentesting-Tool/`  
> **Your branch:** `feature/execution-hardening` · **Friend’s branch:** `feature/multi-agent`

---

## Table of Contents

1. [Your Job in One Page](#1-your-job-in-one-page)
2. [Today in 60 Seconds](#2-today-in-60-seconds)
3. [You vs Friend — The Split](#3-you-vs-friend--the-split)
4. [Join Surface — 4 Things That Must Match](#4-join-surface--4-things-that-must-match)
5. [Parallel Work Map (Friend Phase ↔ You)](#5-parallel-work-map-friend-phase--you)
6. [Today’s Task List (Blocks A–F)](#6-todays-task-list-blocks-af)
7. [Implementation Order (Full List)](#7-implementation-order-full-list)
8. [Integration Contract](#8-integration-contract)
9. [What You Must NOT Do](#9-what-you-must-not-do)
10. [Merge Order — How You Join Work](#10-merge-order--how-you-join-work)
11. [File Ownership](#11-file-ownership)
12. [Pattern Alignment With Friend](#12-pattern-alignment-with-friend)
13. [Competitive Landscape & Scorecard](#13-competitive-landscape--scorecard)
14. [Design North Star](#14-design-north-star)
15. [Win vs Each Tool](#15-win-vs-each-tool)
16. [Backlog After Today](#16-backlog-after-today)
17. [Message to Send Friend](#17-message-to-send-friend)
18. [Definition of Done & Merge Readiness](#18-definition-of-done--merge-readiness)
19. [Appendices](#19-appendices)

---

## 1. Your Job in One Page

**You are the platform.** Friend plugs brains into your sockets.

| You ship | Friend consumes |
|----------|-----------------|
| Tools run reliably in Kali | `execute_tool_request()` |
| Findings after each tool | `findings_store` / structured API |
| Handoff recon → network | `build_handoff_packet()` |
| Situational context in prompt | `build_situational_brief()` |
| YAML hints after failures | `agent_assist` in phase agents |
| Skill **markdown** content | `skills_loader` |
| Smoke script | Pre-PR + CI |

**You don’t ship:** Commander LLM, Summary LLM, phase agent loop, orchestrator.

When both sides done → merge at **`HandoffPacket`** + smoke green on **scanme.nmap.org** → demo.

---

## 2. Today in 60 Seconds

**Morning:** Freeze the **contract** (`HandoffPacket` + structured findings API + smoke script).  
**Afternoon:** **Harden execution** (scanme run, fix red tools) + **YAML/skills** for WAF pivots and evidence-driven dispatch.  
**Evening:** **3 demo differentiators** for manager + confirm branch plan with friend.

You are **not** building Commander/Summary today — that’s friend. You **are** making the platform so their agents plug in cleanly.

---

## 3. You vs Friend — The Split

```
FRIEND (brain)                          YOU (body)
────────────────────────────────────────────────────────────
orchestrator.py                         phase_handoff.py
commander_agent.py                      schemas/agent_run.py
phase_agent.py                          tool_execution.py      ← DO NOT BREAK
summary_llm.py                          command_builder.py
agent.py (wires orchestrator)           mcp_client.py + mcp-servers/
skills_loader (per-agent load)          config/*.yaml
SSE phase labels (cli/display)          agent_assist.py + parsers/
Commander/Recon/Network LLM prompts     findings_store + engagement_graph
                                        skills/*.md CONTENT
                                        scripts/smoke.ps1
                                        INTEGRATION_CONTRACT.md
```

---

## 4. Join Surface — 4 Things That Must Match

1. **`HandoffPacket` schema** — `schemas/agent_run.py` (you land first; friend imports)
2. **`execute_tool_request()`** — stable signature; friend always calls this
3. **`get_tools_for_llm_phase(phase)`** — friend uses; you maintain `recon_network_tools.yaml`
4. **`GET /api/v1/findings/structured`** — you ship; Commander/network agent reads

If you change any of these → update `INTEGRATION_CONTRACT.md` same day and tell friend.

---

## 5. Parallel Work Map (Friend Phase ↔ You)

### Friend Phase 1 — Hardcoded recon → network

| Friend builds | You build (same week) |
|---------------|----------------------|
| `PhaseAgent` + `get_tools_for_llm_phase("recon")` | Verify recon tools on scanme |
| `PhaseAgent` + `get_tools_for_llm_phase("network")` | Verify nmap/MCP in Kali |
| Hardcoded `run_full`: recon then network | **`build_handoff_packet()`** + **`handoff_packet_to_prompt()`** |
| SSE `phase_start` / `phase_done` | Optional: `audit_log` `phase` field |
| Handoff as network agent user message | **`build_situational_brief()` + `handoff_to_prompt()`** |

**You do NOT** refactor `agent_loop.py` on friend’s branch.

### Friend Phase 2 — Summary LLM

| Friend builds | You build |
|---------------|-----------|
| `summary_llm.py` | Keep **parser as ground truth**; extend `parsers/recon_network.py` |
| `ToolSummary` / `PhaseBrief` | Same types in `schemas/agent_run.py` |
| Summary prompts | `skills/summary/summary-overview.md` |

**Do NOT** replace `summary_agent.py` parser with LLM-only.

### Friend Phase 3 — Commander LLM

| Friend builds | You build |
|---------------|-----------|
| `commander_agent.py` | `GET /findings/structured` + `phase_reflection` |
| Final report | `skills/commander/commander-overview.md` |
| Coverage gaps | `tech_dispatch.yaml` + findings populated |

**Do NOT** give Commander direct MCP access.

---

## 6. Today’s Task List (Blocks A–F)

### Block A — Contract & handoff (2–3 h) **CRITICAL**

| # | Task | File(s) | Done? |
|---|------|---------|-------|
| A1 | Pydantic: `HandoffPacket`, `PhaseBrief`, `ToolSummary`, `CommanderDecision` | `schemas/agent_run.py` | ☐ |
| A2 | `build_handoff_packet()` from findings only (no LLM) | `services/phase_handoff.py` | ☐ |
| A3 | `GET /api/v1/findings/structured` | `api/v1/endpoints/findings.py` | ☐ |
| A4 | `docs/INTEGRATION_CONTRACT.md` | docs | ☐ |
| A5 | Branch `feature/execution-hardening`; tell friend | — | ☐ |

**Handoff packet fields:** `target`, `resolved_ip`, `subdomains[]`, `live_urls[]`, `technologies[]`, `primary_hosts[]`, `structured_findings`.

**Constraint keywords (deterministic):**

```python
NO_FULL_PORT_SCAN = ("no full port", "don't full port", "not full port", "-p-", "1-65535")
PASSIVE_ONLY = ("passive only", "passive recon")
```

---

### Block B — Smoke & reproducibility (1 h)

| # | Task | Done? |
|---|------|-------|
| B1 | `scripts/smoke.ps1` | ☐ |
| B2 | Scanme CLI run → `docs/demo_logs/scanme_latest.txt` | ☐ |
| B3 | Fix execution failures (not LLM quota) | ☐ |
| B4 | Update `.env.example` | ☐ |

```powershell
cd "D:\personal work\AI-Pentesting-Tool\llmwork\AI-Pentesting-Tool"
docker compose up -d
curl http://localhost:9000/api/v1/health/
curl http://localhost:9000/api/v1/agent/status
```

---

### Block C — YAML & assist (1–2 h)

| # | Task | File | Done? |
|---|------|------|-------|
| C1 | WAF escalations (path, header, method) | `config/escalation_matrix.yaml` | ☐ |
| C2 | Hint when command has `-p-` / `65535` | `tool_failure_hints.py` | ☐ |
| C3 | Dispatch: URLs found → suggest network | `config/tech_dispatch.yaml` | ☐ |
| C4 | `use_recovery=False` on agent path | `agent_loop.py` | ☐ |

---

### Block D — Skills content (1 h) — you write, friend wires loader

| # | File | Done? |
|---|------|-------|
| D1 | `skills/recon/agent-system.md` | ☐ |
| D2 | `skills/network/agent-system.md` | ☐ |
| D3 | `skills/recon/waf-pivot.md` | ☐ |
| D4 | `skills/commander/commander-overview.md` | ☐ |
| D5 | `skills/summary/summary-overview.md` | ☐ |
| D6 | Expand `skills/network/port-scan-strategy.md` (no full scan) | ☐ |

Templates: [`MULTI_AGENT_HANDOFF_GUIDE.md` §9](./MULTI_AGENT_HANDOFF_GUIDE.md).

---

### Block E — Manager demo (30–45 min)

| # | Task | Done? |
|---|------|-------|
| E1 | Pick top 3 differentiators (Section 18) | ☐ |
| E2 | Optional: `docs/DEMO_TALKING_POINTS.md` | ☐ |

---

### Block F — Git (15 min)

| # | Task | Done? |
|---|------|-------|
| F1 | Branch `feature/execution-hardening` | ☐ |
| F2 | Never commit `.env` | ☐ |
| F3 | Commit: `exec: handoff contract and platform hardening` | ☐ |

---

## 7. Implementation Order (Full List)

### Must-have before friend merges Phase 1

| # | Deliverable | File |
|---|-------------|------|
| 1 | Schema models | `schemas/agent_run.py` |
| 2 | `build_situational_brief()` | `platform/situational_context.py` |
| 3 | `build_handoff_packet()` | `services/phase_handoff.py` |
| 4 | `handoff_packet_to_prompt()` | `services/phase_handoff.py` |
| 5 | Structured findings API | `api/v1/endpoints/findings.py` |
| 6 | Integration contract doc | `docs/INTEGRATION_CONTRACT.md` |
| 7 | Smoke script | `scripts/smoke.ps1` |

### Should-have (same week)

| # | Deliverable |
|---|-------------|
| 8 | YAML WAF + port-scan updates |
| 9 | Skills content (Block D) |
| 10 | Scanme log + execution bugfixes |

### Nice-to-have before final join

| # | Deliverable |
|---|-------------|
| 11 | Audit log `phase` field |
| 12 | Unit test: `build_handoff_packet` |
| 13 | `findings_store.export_for_handoff()` helper |

---

## 8. Integration Contract

### Run a tool

```python
from pentest_platform.schemas.tools import ToolExecutionRequest
from pentest_platform.services.tool_execution import execute_tool_request

response = await execute_tool_request(
    ToolExecutionRequest(
        tool_name="subfinder_scan",
        params={"domain": "scanme.nmap.org"},
        additional_args="-all",
        engagement_id=engagement_id,
        run_id=run_id,
        record_findings=True,
        use_recovery=False,  # REQUIRED on agent path
        timeout=settings.llm.tool_timeout,
    )
)
```

### Tools per phase

```python
from pentest_platform.services.tool_discovery import get_tools_for_llm_phase

recon_tools = get_tools_for_llm_phase("recon", compact=True)
network_tools = get_tools_for_llm_phase("network", compact=True)
```

### Handoff after recon

```python
from pentest_platform.services.phase_handoff import build_handoff_packet, handoff_packet_to_prompt

packet = build_handoff_packet(
    engagement_id=engagement_id,
    run_id=run_id,
    target="scanme.nmap.org",
    resolved_ip="45.33.32.156",
)
prompt_text = handoff_packet_to_prompt(packet)
```

### Findings APIs

```
GET /api/v1/findings/?run_id={run_id}
GET /api/v1/findings/summary?run_id={run_id}
GET /api/v1/findings/structured?run_id={run_id}
```

### Tool result enrichment

Phase agents should keep using `enrich_tool_result_for_agent()` (same as current `agent_loop._execute_tool()`).

Full contract doc: create **`docs/INTEGRATION_CONTRACT.md`** when A4 is done.

---

## 9. What You Must NOT Do

| Don’t | Why |
|-------|-----|
| Edit `orchestrator.py`, `commander_agent.py`, `phase_agent.py` | Friend owns |
| Refactor `agent_loop.py` while friend refactors it | Merge conflict |
| Change `ToolExecutionRequest` without telling friend | Breaks their calls |
| `use_recovery=True` on agent path | HexStrike spam |
| Duplicate `HandoffPacket` in two schema files | One source: `agent_run.py` |
| Work in `new work/` copy | Use **`llmwork/AI-Pentesting-Tool/`** only |

---

## 10. Merge Order — How You Join Work

```
Step 1: YOU merge (execution-hardening):
         schemas/agent_run.py
         phase_handoff.py
         findings/structured endpoint
         INTEGRATION_CONTRACT.md
         skills + yaml
         (no agent_loop refactor)

Step 2: FRIEND rebases feature/multi-agent on top

Step 3: FRIEND imports:
         from pentest_platform.services.phase_handoff import build_handoff_packet, handoff_packet_to_prompt
         from pentest_platform.schemas.agent_run import HandoffPacket

Step 4: TOGETHER — scanme run phase=full; verify handoff has IPs, URLs, situational brief updates

Step 5: Fix only at contract boundary if broken
```

**Weekly sync (15 min):** HandoffPacket changed? Smoke passed?

---

## 11. File Ownership

### Only YOU (edit daily)

```
config/ · mcp-servers/ · kali-tools/ · docker-compose.yml
command_builder.py · tool_execution.py · mcp_client.py
agent_assist.py · tool_failure_hints.py · parsers/
findings_store.py · engagement_graph.py · governance.py
phase_handoff.py · schemas/agent_run.py
api/v1/endpoints/findings.py · skills/ · scripts/smoke.ps1
docs/INTEGRATION_CONTRACT.md · docs/PLATFORM_OWNER_GUIDE.md
```

### Only FRIEND

```
orchestrator.py · commander_agent.py · phase_agent.py · summary_llm.py
agent.py (orchestrator entry) · skills_loader.py (extend)
cli/ui/display.py (phase labels)
```

### COORDINATE first

```
agent_loop.py · core/config.py · schemas/hybrid.py
```

---

## 12. Pattern Alignment With Friend

| Pattern | Your responsibility |
|---------|---------------------|
| Assist, don’t force | YAML → `agent_assist`; no auto-rerun |
| Ground truth | Parsers + findings; handoff from store not LLM prose |
| Phase-scoped tools | Correct `phase:` in `recon_network_tools.yaml` |
| `additional_args` open | Block injection only |
| `use_recovery=False` | Document in contract |
| Same `run_id` | Findings across recon + network |
| `RESOLVED_IP` | `target_utils.resolve_ipv4()` in handoff |

---

## 13. Competitive Landscape & Scorecard

### Landscape

| Product | Strength | Weakness vs us |
|---------|----------|----------------|
| **Shannon** | Multi-agent vuln/exploit, whitebox | Heavy; overkill for recon-only |
| **HexStrike** | 150+ tools | No governed loop; weak memory |
| **Dark-Moon** | WAF workflows | Scripts over NL autonomy |
| **OpenCode plugin** | Live UX | No findings graph / governance |
| **Generic LLM** | Simple | No assist layer |

**Our niche:** **Governed Agentic Execution** — NL agent + YAML assist + Kali + findings memory.

### Scorecard (1–5; raise execution/assist columns)

| Capability | Us | Shannon | HexStrike | Dark-Moon | OpenCode |
|------------|-----|---------|-----------|-----------|----------|
| NL goal | 4 | 4 | 2 | 2 | 5 |
| Free tool/flag choice | 4 | 3 | 2 | 2 | 5 |
| `additional_args` | 5 | 3 | 3 | 3 | 4 |
| Live SSE | 4 | 3 | 2 | 2 | 5 |
| Findings memory | 3→4* | 4 | 1 | 2 | 1 |
| Failure hints | 4 | 4 | 3 | 4 | 2 |
| Governance | 4 | 5 | 1 | 2 | 1 |
| Multi-phase | 2→4† | 5 | 1 | 4 | 2 |
| LLM summary | 1→4† | 4 | 1 | 2 | 3 |

\*After handoff + structured API · †After friend ships multi-agent

---

## 14. Design North Star

```
1. ASSIST, DON'T FORCE     YAML/skills suggest; LLM decides
2. GROUND TRUTH            Parsers + findings beat LLM prose
3. READ THE STDERR         stdout/stderr + HINTs every tool
4. NO DUMB LOOPS           Repeat warning + session findings
5. GOVERNED                Scope, injection block, RoE
6. EXPERT FLAGS            additional_args within safety
7. PHASE CLARITY           Recon discovers; network probes; structured handoff
8. OBSERVABLE              SSE, audit, smoke script
9. COMPOSABLE              Stable execute_tool_request API
10. DEMO-SAFE              scanme.nmap.org <10 min
```

**Anti-patterns:** fixed YAML-only path · HexStrike auto-recovery · 90 tools at once · LLM-only handoff

---

## 15. Win vs Each Tool

| vs | Your action | Friend action |
|----|-------------|---------------|
| **Shannon** | handoff + structured API, skills content, audit phase | orchestrator, Commander report |
| **HexStrike** | curated 24 tools, escalation hints only, command_builder fixes | — |
| **Dark-Moon** | escalation_matrix + waf-pivot skills; workflows API-only | — |
| **OpenCode** | SSE + findings layer | phase labels in CLI |
| **Generic LLM** | repeat warning, situational brief, structured API | — |

**Manager one-liner:**

> Governed AI pentest: real Kali tools + memory + safety + smart pivots — Shannon-style phases without Shannon infra, HexStrike tools without the monolith, full flag flexibility, no rigid scripts.

---

## 16. Backlog After Today

| P | Item |
|---|------|
| P0 | `phase_handoff.py` + tests |
| P0 | Structured findings API |
| P1 | Smoke in CI; audit `phase` field |
| P1 | command_builder docs |
| P2 | Postgres findings; hybrid context for Commander |
| P2 | Expand parsers (wayback, hakrawler) |
| P3 | DEMO_TALKING_POINTS.md |

---

## 17. Message to Send Friend

**Subject: Integration contract — execution layer**

Working in `llmwork/AI-Pentesting-Tool/`.

- **Your branch:** `feature/multi-agent`
- **My branch:** `feature/execution-hardening`
- **My guide:** `docs/PLATFORM_OWNER_GUIDE.md`
- **Your guide:** `docs/MULTI_AGENT_HANDOFF_GUIDE.md`

**Call (don’t reimplement):**

- `execute_tool_request(..., use_recovery=False)`
- `get_tools_for_llm_phase("recon"|"network")`
- `build_handoff_packet()` / `handoff_packet_to_prompt()` (I ship in `phase_handoff.py`)
- `GET /api/v1/findings/structured?run_id=`

**Don’t change without sync:** `command_builder.py`, `mcp_client.py`, `mcp-servers/`

**Smoke before PR:** `scripts/smoke.ps1`

---

## 18. Definition of Done & Merge Readiness

### End of day

- [ ] `HandoffPacket` + `build_handoff_packet()` works
- [ ] `GET /api/v1/findings/structured` works
- [ ] `INTEGRATION_CONTRACT.md` exists
- [ ] Scanme run ≥3 tools OK; log saved
- [ ] WAF + no-full-scan in YAML/skills
- [ ] Friend has branch plan + this doc

### Ready for friend merge?

```powershell
cd llmwork\AI-Pentesting-Tool
docker compose up -d
$env:PYTHONPATH="backend\src"
python -c "from pentest_platform.services.phase_handoff import build_handoff_packet; print('OK')"
curl http://localhost:9000/api/v1/findings/structured?run_id=test
.\scripts\smoke.ps1
```

### Three demo differentiators

1. **Governed autonomy** — LLM picks tools/flags; platform governs + remembers + hints  
2. **Assist layer** — HINTs, OPTIONAL SUGGESTIONS, SESSION FINDINGS, repeat warnings  
3. **Composable multi-agent** — handoff packet + phase tools; friend’s Commander plugs in  

---

## 19. Appendices

### A — `phase_handoff.py` spec

```python
def build_situational_brief(...) -> str: ...

def build_handoff_packet(
    *, engagement_id: str, run_id: str, target: str,
    resolved_ip: str | None = None,
) -> HandoffPacket: ...

def handoff_packet_to_prompt(packet: HandoffPacket) -> str: ...
```

### B — Structured findings API shape

```json
{
  "target": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "subdomains": ["scanme.nmap.org"],
  "live_urls": ["http://scanme.nmap.org:80"],
  "open_services": ["scanme.nmap.org:22/tcp ssh"],
  "technologies": [],
  "text_summary": "..."
}
```

### C — Related docs

- [`MULTI_AGENT_HANDOFF_GUIDE.md`](./MULTI_AGENT_HANDOFF_GUIDE.md) — friend  
- [`ARCHITECTURE_AND_WORKFLOW_EXPLAINED.md`](./ARCHITECTURE_AND_WORKFLOW_EXPLAINED.md) — demo  
- [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) — create with Block A  
- [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md) — vision  

---

*Single doc for platform owner: today’s tasks, parallel work with friend, merge plan, and competitive strategy. Check boxes in Section 6 & 18 as you go.*
