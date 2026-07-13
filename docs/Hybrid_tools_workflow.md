# Hybrid Tools Workflow — Recon & Network

> **Scope:** Everything implemented for the **recon + network hybrid layer** in `new work/AI-Pentesting-Tool/`.  
> **Audience:** You (execution/tools) and your friend (Commander LLM / chat endpoint).  
> **Related:** [`TOOLS_LAYER_ANALYSIS.md`](./TOOLS_LAYER_ANALYSIS.md) covers the base tools layer in depth.

---

## Table of Contents

1. [What This Layer Does](#1-what-this-layer-does)
2. [Why We Built It This Way](#2-why-we-built-it-this-way)
3. [Architecture At a Glance](#3-architecture-at-a-glance)
4. [Complete File Inventory](#4-complete-file-inventory)
5. [How Data Flows — Three Execution Paths](#5-how-data-flows--three-execution-paths)
6. [Step-by-Step: Single Tool Run](#6-step-by-step-single-tool-run)
7. [Step-by-Step: Workflow Run](#7-step-by-step-workflow-run)
8. [Step-by-Step: Commander Turn](#8-step-by-step-commander-turn)
9. [API Reference](#9-api-reference)
10. [Config Files Explained](#10-config-files-explained)
11. [How This Helps Your Friend’s LLM](#11-how-this-helps-your-friends-llm)
12. [Quick Start Commands](#12-quick-start-commands)

---

## 1. What This Layer Does

The hybrid recon/network layer sits **between** the Commander LLM (your friend builds) and the **90 HexStrike tools** running in Kali.

It provides:

1. **Structured execution** — LLM sends `tool_name` + `params` + `additional_args`, never raw shell.
2. **Memory between turns** — findings store + engagement graph so the next prompt knows what was already discovered.
3. **Guidance without rigidity** — tasks, skills, dispatch rules, and escalation hints; the LLM still chooses tools and flags.
4. **Multi-step workflows** — optional pre-built chains (e.g. subfinder → httpx) the LLM can call as one action.
5. **Automatic hints after every run** — escalation, dispatch, and graph pivot suggestions returned in `response.hybrid`.

**Phases covered:** `recon` and `network` only.

---

## 2. Why We Built It This Way

### Problem before this work

- Tools could run, but the LLM had **no shared memory** between calls.
- There was **no standard packet** for your friend to load catalog + methodology + prior results.
- Failed or thin tool output did **not** suggest what to try next.
- Running subfinder then httpx required **two manual API calls** with copy-paste between them.
- Cross-host relationships (same IP, sibling subdomains) were **not tracked**.

### What the hybrid layer fixes

| Design choice | Benefit |
|---------------|---------|
| **Single `tool_execution.py` pipeline** | Workflows and `/mcp/execute` use the same govern → validate → run → parse path — no drift. |
| **`response.hybrid` on every run** | Commander gets next-step hints without a separate planning call. |
| **`GET /hybrid/context/{phase}`** | One HTTP call loads everything needed for a system prompt. |
| **YAML-driven escalation + dispatch** | You can tune pivot rules without changing Python. |
| **Engagement graph** | Findings become queryable structure (siblings on same IP, open ports → SMB task). |
| **`additional_args` unrestricted** | LLM can pass any CLI flags; platform only blocks shell metacharacters. |
| **Workflows optional** | LLM can chain tools itself *or* call a workflow when that’s faster. |

---

## 3. Architecture At a Glance

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Commander LLM (friend) — not built yet                                  │
│  Loads context → proposes tool OR workflow → reads hybrid hints          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 GET /hybrid/context      POST /hybrid/workflows   POST /mcp/execute
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                    services/tool_execution.py
                                │
     ┌──────────────────────────┼──────────────────────────┐
     ▼                          ▼                          ▼
 governance.py           param_validator.py         command_builder.py
     │                          │                          │
     └──────────────────────────┼──────────────────────────┘
                                ▼
                    services/mcp_client.py
                    (docker exec → Kali tools)
                                │
                                ▼
                    services/summary_agent.py
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
    services/findings_store.py      services/engagement_graph.py
              │                                   │
              └─────────────────┬─────────────────┘
                                ▼
              escalation_registry + tech_dispatch + recovery_bridge
                                │
                                ▼
                    response.hybrid { hints }
```

---

## 4. Complete File Inventory

### 4.1 Config (project root `config/`)

| File | Purpose |
|------|---------|
| `recon_network_tools.yaml` | **Task + tool catalog for LLM** — 8 tasks, tool parameters, `llm_hints`, example calls. Loaded by `task_registry.py`. |
| `escalation_matrix.yaml` | **What to try when a tool fails or returns thin results** — WAF pivots, fallback tool chains, flag adjustments. Loaded by `escalation_registry.py`. |
| `tech_dispatch.yaml` | **Signal → next task rules** — e.g. port 445 open → suggest `smb_enumeration`, few subdomains → suggest amass. Loaded by `tech_dispatch.py`. |
| `workflows.yaml` | **Multi-step tool chains** — `subdomain_discovery`, `port_scan_pipeline`, etc. Loaded by `workflow_runner.py`. |

### 4.2 Skills (`skills/`)

Markdown methodology injected into Commander prompts via `skills_loader.py`.

| Path | Purpose |
|------|---------|
| `recon/phase-overview.md` | Recon phase goals and suggested order |
| `recon/subdomain-enumeration.md` | When/how to use subfinder, amass, fierce |
| `recon/live-host-probing.md` | httpx usage and useful flags |
| `recon/historical-url-discovery.md` | waybackurls, gau |
| `recon/web-crawling.md` | hakrawler |
| `recon/dns-intelligence.md` | dnsenum, fierce |
| `network/phase-overview.md` | Network phase goals |
| `network/port-scan-strategy.md` | rustscan, masscan, nmap |
| `network/service-enumeration.md` | nmap service scans |
| `network/smb-enumeration.md` | enum4linux, smbmap when 445 open |
| `shared/finding-confidence.md` | confirmed / likely / hypothesis |
| `shared/governance-rules.md` | scope and proposal rules |
| `shared/tool-selection-ux.md` | 5-second override UX notes for friend |
| `shared/escalation-playbook.md` | **New** — when/how to escalate after blocks |
| `shared/sister-domain-discovery.md` | **New** — shared IP / sibling host pivoting |

### 4.3 Schemas (`backend/src/pentest_platform/schemas/`)

| File | Purpose |
|------|---------|
| `tool_call.py` | `ToolCallProposal` — what the LLM should emit; `ToolCallValidationResult`. |
| `finding.py` | `Finding`, `FindingType`, `FindingConfidence` — structured observations. |
| `tool_capability.py` | `TaskDefinition`, `ToolCapability` — LLM catalog shapes. |
| `tools.py` | `ToolExecutionRequest/Response` — includes `additional_args`, `run_id`, `record_findings`, and **`hybrid`** dict on response. |
| `engagement_graph.py` | **New** — `AssetNode`, `GraphSummary`, `SiblingHostResponse`. |
| `hybrid.py` | **New** — `CommanderContext`, `WorkflowRunRequest/Response`, `EscalationSuggestion`, `DispatchSuggestion`, `PhaseReflection`, `HybridExecutionMeta`. |

### 4.4 Services — base tools layer (built first)

| File | Purpose |
|------|---------|
| `command_builder.py` | Imports harvested `build_command()` from `mcp-servers/`, merges LLM `additional_args`. Single CLI builder for all paths. |
| `param_validator.py` | Blocks shell metacharacters only; does **not** whitelist flags. |
| `task_registry.py` | Loads `recon_network_tools.yaml`; exposes `llm_tool_catalog_for_phase()`. |
| `skills_loader.py` | Concatenates phase skills + shared skills into one markdown string. |
| `findings_store.py` | In-memory list of `Finding` objects; `summary_for_agent()` for prompts. |
| `summary_agent.py` | After successful run: parse stdout → findings → **also updates engagement graph**. |
| `parsers/recon_network.py` | Deterministic parsers for subfinder, httpx, nmap, rustscan stdout. |
| `mcp_client.py` | Runs tools in Kali via `docker exec`; uses `command_builder`. |
| `tool_registry.py` | All 90 tools; includes `additional_args` on every tool. |
| `governance.py` | Scope/safety checks before execution. |
| `audit_log.py` | Records every tool run. |
| `engagement_store.py` | Engagement scope/RoE lookup. |

### 4.5 Services — hybrid layer (built second)

| File | Purpose |
|------|---------|
| `engagement_graph.py` | **Memory graph** — ingests findings as nodes/edges; answers “who shares this IP?” |
| `escalation_registry.py` | Loads `escalation_matrix.yaml`; detects signals (WAF, timeout, few results); returns `EscalationSuggestion` list. |
| `tech_dispatch.py` | Loads `tech_dispatch.yaml`; reads findings + graph; returns recommended next tasks/tools. |
| `recovery_bridge.py` | On failure, calls HexStrike `process_tool_failure()` from `mcp-servers/_core/error_handler.py` for extra recovery hints. |
| `workflow_runner.py` | Runs multi-step workflows from `workflows.yaml`; each step calls `tool_execution.py`. |
| `commander_context.py` | Builds one `CommanderContext` object — catalog + skills + findings + graph + dispatch + coverage gaps. |
| `phase_reflection.py` | Checks recon/network coverage (what’s done vs missing); suggests workflows. |
| `tool_execution.py` | **Central pipeline** used by `/mcp/execute` and workflows; attaches `response.hybrid`. |

### 4.6 API endpoints

| File | Routes | Purpose |
|------|--------|---------|
| `endpoints/capabilities.py` | `/capabilities/*` | Tool catalog, validate, build-command preview, skills |
| `endpoints/findings.py` | `/findings/*` | List findings, text summary |
| `endpoints/mcp.py` | `POST /mcp/execute` | Thin wrapper → `tool_execution.execute_tool_request()` |
| `endpoints/hybrid.py` | `/hybrid/*` | Context, workflows, escalation, dispatch, graph, reflection |
| `router.py` | — | Registers all routers under `/api/v1` |

### 4.7 Execution backend (unchanged by hybrid, but used by it)

| Path | Purpose |
|------|---------|
| `mcp-servers/{recon,network}/tools/*.py` | Harvested HexStrike modules — each has `build_command(**params)`. |
| `mcp-servers/_core/error_handler.py` | Error classification and recovery strategies (used by `recovery_bridge.py`). |

---

## 5. How Data Flows — Three Execution Paths

The Commander (your friend) can drive recon/network in **three ways**. All paths end with findings + graph updates + hybrid hints.

### Path A — Single tool (maximum LLM freedom)

```
POST /api/v1/mcp/execute
  → tool_execution.py
  → Kali
  → summary_agent → findings_store + engagement_graph
  → escalation + dispatch + graph pivots → response.hybrid
```

**When to use:** LLM wants full control over tool choice, params, and `additional_args`.

### Path B — Workflow (pre-built chain)

```
POST /api/v1/hybrid/workflows/subdomain_discovery/run
  → workflow_runner.py
  → step 1: tool_execution (subfinder)
  → step 2: tool_execution (httpx, fed with step 1 subdomains)
  → WorkflowRunResponse with all step results + dispatch + graph
```

**When to use:** Common sequence (enum → probe, fast scan → service scan) without LLM managing handoff.

### Path C — Context-first Commander turn

```
GET /api/v1/hybrid/context/recon?engagement_id=&run_id=
  → commander_context.py assembles everything
  → LLM reads context, then uses Path A or B
  → GET /hybrid/reflection/recon to check coverage gaps
```

**When to use:** Start of each chat turn or after several tool runs.

---

## 6. Step-by-Step: Single Tool Run

**Example:** `subfinder_scan` on `example.com` with extra flags.

### Request

```http
POST /api/v1/mcp/execute
Content-Type: application/json

{
  "tool_name": "subfinder_scan",
  "params": { "domain": "example.com" },
  "additional_args": "-all -recursive",
  "engagement_id": "eng-001",
  "run_id": "run-001",
  "record_findings": true
}
```

### Internal steps

| Step | File | What happens |
|------|------|--------------|
| 1 | `tool_registry.py` | Confirm `subfinder_scan` exists |
| 2 | `governance.py` | Check target `example.com` against engagement scope |
| 3 | `param_validator.py` | Approve flags; reject shell metacharacters |
| 4 | `command_builder.py` | Load `mcp-servers/recon/tools/subfinder_scan.py` → `build_command()` |
| 5 | `mcp_client.py` | `docker exec kali-tools bash -c "subfinder -d example.com ..."` |
| 6 | `summary_agent.py` | `parse_subfinder(stdout)` → list of `Finding` |
| 7 | `findings_store.py` | Store findings |
| 8 | `engagement_graph.py` | Add subdomain nodes (and IP edges if present) |
| 9 | `escalation_registry.py` | If few subdomains, suggest amass/fierce |
| 10 | `tech_dispatch.py` | If signals match, suggest next task (e.g. httpx) |
| 11 | `audit_log.py` | Record run |

### Response shape

```json
{
  "tool_name": "subfinder_scan",
  "success": true,
  "command": "subfinder -d example.com -silent -all -recursive",
  "stdout": "api.example.com\nwww.example.com\n...",
  "hybrid": {
    "escalation_suggestions": [],
    "dispatch_suggestions": [
      {
        "signal": "live_hosts_found",
        "task_id": "historical_url_discovery",
        "default_tool": "waybackurls_discovery",
        "reason": "..."
      }
    ],
    "graph_pivots": ["Subdomains found but no port scan — run port_discovery workflow"]
  }
}
```

---

## 7. Step-by-Step: Workflow Run

**Example:** `subdomain_discovery` workflow.

### Request

```http
POST /api/v1/hybrid/workflows/subdomain_discovery/run

{
  "params": { "domain": "example.com" },
  "engagement_id": "eng-001",
  "run_id": "run-001"
}
```

### Defined in `config/workflows.yaml`

```yaml
steps:
  - id: enum
    tool: subfinder_scan
    params: { domain: "{{domain}}" }
    additional_args: "-all"
  - id: probe
    tool: httpx_probe
    feed_findings_from: enum
    finding_type: subdomain
    join: newline
    param: target
    additional_args: "-td -sc -title -status-code"
```

### Internal steps

| Step | File | What happens |
|------|------|--------------|
| 1 | `workflow_runner.py` | Load workflow definition |
| 2 | Step `enum` | Substitute `{{domain}}` → call `execute_tool_request()` |
| 3 | `summary_agent` | Parse subdomains into findings + graph |
| 4 | Step `probe` | Collect subdomain titles from step findings → join as httpx `target` |
| 5 | Step `probe` | Run httpx on all hosts |
| 6 | End | Return `WorkflowRunResponse` with per-step results, dispatch, graph summary |

### Why workflows help

- **No manual handoff** — subfinder output automatically becomes httpx input.
- **Same governance/validation** as single tools — every step goes through `tool_execution.py`.
- **LLM can still override** — it can ignore workflows and call tools individually anytime.

---

## 8. Step-by-Step: Commander Turn

What your friend’s agent loop should do each turn:

```
1. GET /api/v1/hybrid/context/recon?engagement_id=eng-001&run_id=run-001

   Returns CommanderContext:
   - catalog        → tools/tasks for function calling
   - skills         → markdown methodology
   - findings_summary → prior discoveries as text
   - graph_summary  → subdomains, live hosts, ports, pivot_hints
   - dispatch_rules → recommended next tasks right now
   - coverage_gaps  → what's still missing in this phase
   - escalation_playbook → markdown for blocked runs

2. LLM decides:
   - POST /mcp/execute  (one tool), OR
   - POST /hybrid/workflows/{id}/run  (chain)

3. Read response.hybrid on each execution:
   - escalation_suggestions → retry with different tool/flags
   - dispatch_suggestions → pivot to new task
   - graph_pivots         → check sibling hosts, etc.

4. Optional checks:
   GET /hybrid/graph/siblings?host=api.example.com
   GET /hybrid/reflection/recon
   POST /hybrid/escalation/suggest  (if need manual escalation query)
```

---

## 9. API Reference

### Hybrid (`/api/v1/hybrid`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/context/{recon\|network}` | Full Commander context packet |
| GET | `/workflows?phase=` | List available workflows |
| GET | `/workflows/{id}` | Workflow definition detail |
| POST | `/workflows/{id}/run` | Execute multi-step workflow |
| POST | `/escalation/suggest` | Get escalation suggestions from error/output |
| GET | `/dispatch/suggest` | Get task/tool dispatch suggestions |
| GET | `/graph/summary` | Graph counts and pivot hints |
| GET | `/graph/siblings?host=` | Hosts sharing same IP |
| GET | `/reflection/{recon\|network}` | Phase coverage check |

### Tools layer (used alongside hybrid)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/capabilities/phases/{phase}/llm-catalog` | Tool schemas for function calling |
| GET | `/capabilities/skills/{phase}` | Skills markdown only |
| POST | `/capabilities/validate` | Pre-flight validate `ToolCallProposal` |
| POST | `/capabilities/build-command` | Preview CLI command |
| POST | `/mcp/execute` | Run one tool |
| GET | `/findings/summary` | Findings text for prompts |
| GET | `/findings/` | Full finding list |

---

## 10. Config Files Explained

### `escalation_matrix.yaml`

Organized by **technique** (e.g. `subdomain_enumeration`, `port_discovery`):

- **`blocked_signals`** — WAF, 403, rate limit → suggest path/flag/tool change
- **`thin_results_signals`** — success but fewer than 5 lines → suggest deeper enum
- **`escalations`** — concrete actions: `alternate_tool`, `adjust_params`, `graph_pivot`
- **`fallback_chains`** — ordered tool list when no specific rule matches

**Example rule:** subfinder returns 3 hosts → suggest `amass_scan` with `-passive`.

### `tech_dispatch.yaml`

Organized by **signals detected in findings/graph**:

- Few subdomains → dispatch `amass_scan`
- Port 445 in metadata → dispatch `smb_enumeration`
- Open ports but no services → dispatch `nmap_service_scan`
- Multiple siblings on same IP → dispatch httpx on siblings

Each rule has a **priority** — higher priority suggestions appear first.

### `workflows.yaml`

Organized by **workflow id**:

| Workflow | Phase | Steps |
|----------|-------|-------|
| `subdomain_discovery` | recon | subfinder → httpx |
| `deep_subdomain_discovery` | recon | subfinder → amass (if <5) → httpx |
| `port_scan_pipeline` | network | rustscan → nmap_service (ports fed forward) |
| `smb_followup` | network | enum4linux → smbmap |

Template syntax: `{{domain}}`, `{{target}}` replaced from workflow `params`.

Special step keys:

- `feed_findings_from` — pass prior step’s findings into next tool param
- `feed_ports_from` — pass discovered ports into nmap `ports` param
- `skip_if_prior_findings_gte` — skip amass if subfinder already found enough

### `recon_network_tools.yaml`

Maps **tasks** to **tools** for the LLM catalog:

- 5 recon tasks + 3 network tasks
- Per-tool parameters, `llm_hints`, `example_calls`
- Explicit note: examples are hints; `additional_args` is unrestricted

---

## 11. How This Helps Your Friend’s LLM

| Need | How hybrid layer helps |
|------|------------------------|
| Know what tools exist | `GET /hybrid/context/{phase}` → `catalog` |
| Know methodology | Same response → `skills` |
| Remember prior runs | Same response → `findings_summary` + `graph_summary` |
| Decide what’s next | `dispatch_rules`, `coverage_gaps`, `response.hybrid.dispatch_suggestions` |
| Recover from failure | `response.hybrid.escalation_suggestions`, `POST /escalation/suggest` |
| Pivot on shared hosting | `GET /graph/siblings`, `graph_pivots` in hybrid response |
| Run common sequences | `POST /workflows/{id}/run` |
| Use any CLI flag | `additional_args` on every execute call |
| Check phase completeness | `GET /reflection/{phase}` |

Your friend **does not** need to implement parsing, graphing, or escalation logic — only the chat loop that calls these APIs and passes `ToolCallProposal`-shaped JSON.

---

## 12. Quick Start Commands

```bash
# Start backend (from project root, with Kali container running)
cd backend
uvicorn pentest_platform.main:app --reload --port 8000

# 1. Load Commander context for recon
curl "http://localhost:8000/api/v1/hybrid/context/recon?engagement_id=demo&run_id=r1"

# 2. Run single tool
curl -X POST http://localhost:8000/api/v1/mcp/execute \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"subfinder_scan","params":{"domain":"example.com"},"additional_args":"-all","engagement_id":"demo","run_id":"r1"}'

# 3. Run workflow
curl -X POST http://localhost:8000/api/v1/hybrid/workflows/subdomain_discovery/run \
  -H "Content-Type: application/json" \
  -d '{"params":{"domain":"example.com"},"engagement_id":"demo","run_id":"r1"}'

# 4. Check graph + reflection
curl "http://localhost:8000/api/v1/hybrid/graph/summary?engagement_id=demo&run_id=r1"
curl "http://localhost:8000/api/v1/hybrid/reflection/recon?engagement_id=demo&run_id=r1"

# 5. Get dispatch suggestions after findings exist
curl "http://localhost:8000/api/v1/hybrid/dispatch/suggest?engagement_id=demo&run_id=r1"
```

---

## Summary

The hybrid recon/network layer turns isolated tool runs into a **connected system**:

- **Execute** safely with governance and free-form flags
- **Remember** via findings + graph
- **Guide** via skills, dispatch, and escalation YAML
- **Chain** via workflows when useful
- **Hint** after every run via `response.hybrid`

Your friend plugs a LiteLLM Commander on top of `GET /hybrid/context/*` and `POST /mcp/execute` or workflow endpoints. You own everything below that line.
