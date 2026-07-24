# Hybrid Autonomous Pentest Platform — Blueprint

> ⚠️ **This is the forward-looking north-star vision** (full lifecycle: business logic, token/WAF bypass, exploit dev, kill chains). For what is actually **built today** (recon + network), see [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md). Inline citations to `Tool_architecture.md` / `analysis.md` are historical research notes now absorbed here and into the [`../Comparative Analysis/`](../Comparative%20Analysis/) HTML analyses.

> **Purpose:** Synthesize **Shannon (core)**, **Shannon OpenCode Plugin**, **Dark-Moon**, and **HexStrike** into a single architecture that exceeds each individually — with full LLM freedom to chain tools, test business logic, bypass tokens/WAFs, and develop exploits under governance.  
> **Audience:** Platform builders.  
> **Related:** [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md) · [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) · [`../Comparative Analysis/`](../Comparative%20Analysis/)

---

## Table of Contents

1. [What “Unbeatable” Means Here](#1-what-unbeatable-means-here)
2. [The Four Reference Systems — Deep Analysis](#2-the-four-reference-systems--deep-analysis)
3. [Comparative Matrix](#3-comparative-matrix)
4. [Lessons From Real Campaigns (samaa.tv Pattern)](#4-lessons-from-real-campaigns-samaatv-pattern)
5. [Hybrid Architecture — Four Planes](#5-hybrid-architecture--four-planes)
6. [The Commander Model — LLM Chain Freedom](#6-the-commander-model--llm-chain-freedom)
7. [Execution Layer — HexStrike + Governed Bridge](#7-execution-layer--hexstrike--governed-bridge)
8. [Identity & Auth Plane — Shannon Plugin Patterns](#8-identity--auth-plane--shannon-plugin-patterns)
9. [Browser & SPA Plane](#9-browser--spa-plane)
10. [Business Logic & Token Bypass Testing](#10-business-logic--token-bypass-testing)
11. [Exploit Development & Post-Exploitation Plane](#11-exploit-development--post-exploitation-plane)
12. [Validation & Findings — Shannon Rigor](#12-validation--findings--shannon-rigor)
13. [Multi-Agent Dispatch — Dark-Moon Patterns](#13-multi-agent-dispatch--dark-moon-patterns)
14. [Whitebox Code Analysis — Shannon Core](#14-whitebox-code-analysis--shannon-core)
15. [Escalation Matrix (WAF / Block / Dead-End)](#15-escalation-matrix-waf--block--dead-end)
16. [Tool Surface Design — Not 90 Functions At Once](#16-tool-surface-design--not-90-functions-at-once)
17. [End-to-End Flow — Hybrid Campaign Example](#17-end-to-end-flow--hybrid-campaign-example)
18. [Implementation Roadmap](#18-implementation-roadmap)
19. [Component status](#19-component-status)
20. [Appendix: Source Locations In This Workspace](#20-appendix-source-locations-in-this-workspace)

---

## 1. What “Unbeatable” Means Here

“Unbeatable” does **not** mean “one LLM prompt that hacks everything.” It means a platform where:

| Capability | Why it matters | Best current reference |
|------------|----------------|------------------------|
| **Breadth** | Recon → web → cloud → binary → exploit in one engagement | HexStrike (90 tools) |
| **Depth** | Confirmed findings, exploitation evidence, MITRE/CVSS | Shannon core |
| **Exploration** | Pivot on signals; sister domains; tech-aware dispatch | Dark-Moon |
| **Auth & logic** | Sessions, registration flows, IDOR, rate limits, JWT | Shannon plugin |
| **LLM freedom** | Model chooses tool, params, **any flags**, chain order | Dark-Moon + your `additional_args` design |
| **Safety** | Scope, approval gates, audit, no raw shell from LLM | Dark-Moon MCP gate + Shannon governance |
| **Durability** | 6-hour runs survive crashes | Shannon Temporal |
| **Model agnostic** | Swap Opus/GPT/local without rewrite | Dark-Moon + Shannon plugin |

**The hybrid wins by composing planes**, not by copying one repo wholesale:

```
Dark-Moon's reactive orchestration
+ Shannon's validation & durable workflow
+ HexStrike's execution breadth
+ Shannon plugin's auth/browser/logic tooling
+ Your Governed Agentic Execution (GAE) bridge (ToolCallProposal, command_builder, findings)
= platform that can do anything each tool does, with LLM-chosen chains
```

---

## 2. The Four Reference Systems — Deep Analysis

### 2.1 Shannon (Core) — Keygraph Temporal Whitebox Pipeline

**Location:** `shannon/shannon/` (monorepo: `apps/cli/`, `apps/worker/`)

#### Architecture

Shannon is a **fixed five-phase pipeline** orchestrated by **Temporal**:

```
Preflight → Auth validation → Pre-recon (code) → Recon → [5 parallel vuln→exploit pipelines] → Report
```

Each phase is a **dedicated agent** with its own prompt template, deliverable file, and optional MCP **collector** (structured one-shot tools that feed deterministic renderers).

#### How tools are invoked

| Mechanism | Description |
|-----------|-------------|
| **Claude Agent SDK** | `runClaudePrompt()` with `permissionMode: 'bypassPermissions'` |
| **Built-in SDK tools** | Bash, Read, Edit, Task (sub-agents), TodoWrite |
| **Browser** | `playwright-cli` skill with per-agent session isolation |
| **MCP collectors** | In-process `createSdkMcpServer()` — **not** HexStrike-style CLI farm |
| **Deliverables** | `save-deliverable` CLI → `.shannon/deliverables/` |

Collectors (`pre-recon-collector`, `recon-collector`, `vuln-collector`, `exploit-collector`) use **Zod schemas**. The LLM fills structured sections; renderers produce markdown without format drift.

#### Agent taxonomy (fixed)

| Vuln class | Vuln agent | Exploit agent |
|------------|------------|---------------|
| injection | `injection-vuln` | `injection-exploit` |
| xss | `xss-vuln` | `xss-exploit` |
| auth | `auth-vuln` | `auth-exploit` |
| authz | `authz-vuln` | `authz-exploit` |
| ssrf | `ssrf-vuln` | `ssrf-exploit` |

Config can subset via `vuln_classes` and disable exploitation with `exploit: false`.

#### Governance strengths

- **Preflight:** repo exists, DNS/HTTP checks, blocks cloud metadata IPs
- **Run scope lock:** `vuln_classes` + `exploit` persisted; resume fails if scope changes
- **Code path rules:** `rules.avoid` / `rules.focus` → SDK deny rules in `~/.claude/settings.json`
- **Rules of engagement:** free-text injected into every prompt
- **Auth preflight:** real browser login → `auth-state.json` for session reuse
- **Queue validation:** vuln deliverable + exploitation queue must exist symmetrically
- **Finding status:** confirmed vs hypothesis via structured JSON queues

#### Strengths

1. **Durable orchestration** — Temporal survives crashes, supports resume
2. **Parallel pipelining** — 5 vuln classes don't block each other
3. **Deterministic deliverables** — renderers + Zod reduce LLM format chaos
4. **Whitebox depth** — source repo analysis in pre-recon/recon
5. **Professional reporting** — executive report assembly, MITRE mapping

#### Limitations (for “do anything” autonomy)

1. **Fixed OWASP taxonomy** — no cloud/binary/API phases without registry + workflow changes
2. **Claude SDK coupling** — tool surface is SDK-specific despite multi-provider backends
3. **`bypassPermissions` + Bash** — flexible but weak execution governance vs `ToolCallProposal`
4. **Whitebox required** — `-r repo` mandatory; poor for pure blackbox
5. **No progressive tool catalog** — all context loaded per phase, not task-scoped
6. **Checklist rigidity** — misses novel vuln classes (e.g. live defacement on sister subdomain)

**Key files:**

- `apps/worker/src/temporal/workflows.ts` — pipeline
- `apps/worker/src/session-manager.ts` — agent registry
- `apps/worker/src/ai/claude-executor.ts` — SDK invocation
- `apps/worker/src/mcp-server/*-collector.ts` — structured collectors
- `apps/worker/prompts/` — agent templates + `shared/` partials

---

### 2.2 Shannon OpenCode Plugin — Blackbox Web Pentest Extension

**Location:** `shannon_plugin/opencode-shannon-plugin/`

#### What it is

A **port of Shannon methodology** to **OpenCode** (any LLM provider). Not Temporal — the **LLM is the orchestrator**. Tools run via `docker exec` into `shannon-tools` Kali container.

#### Registered tools (~20)

| Tool | Purpose |
|------|---------|
| `shannon_docker_init` / `cleanup` | Container lifecycle |
| `shannon_exec` | **Arbitrary shell escape hatch** in container |
| `shannon_recon` / `vuln_discovery` / `exploit` / `report` | Phase wrappers |
| `shannon_auth_session` | JWT/cookie/header sessions; automated login with email/username+password |
| `shannon_browser` | User-supplied **Python/Playwright** scripts in container |
| `shannon_idor_test` | Manual curl or **auto 17 REST patterns** with auth token |
| `shannon_upload_test` | XXE, polyglot, extension bypass |
| `shannon_rate_limit_test` | burst / timing / **race** (login brute, coupon races) |
| `shannon_js_analyze` | Static JS: API keys, **emails**, endpoints, XSS sinks |
| `shannon_crawler` | passive/active/authenticated/js crawl; finds `/register`, `/login` |
| `shannon_param_fuzz` | Hidden parameter discovery |
| `shannon_api_fuzzer` | GraphQL introspection, REST, gRPC reflection |
| `shannon_tls_scan` / `headers_audit` / `subdomain_takeover` | Infrastructure checks |

#### Auth & “email registration” (clarification)

There is **no disposable-email registration service**. “Registration” means:

1. **Testing registration endpoints** — role injection (`role: admin`), stored XSS in email field, enumeration via duplicate-email errors (documented in `system-prompt.ts`)
2. **Auth session with email credentials** — `shannon_auth_session` POSTs to login with `{ email, password }`, extracts JWT/cookies
3. **Emails extracted from JS** — `shannon_js_analyze` finds addresses in bundles

Automated login flow (`shannon-auth-session/tools.ts`):

```
create → POST login_endpoint with credentials → parse token/cookies → session_id
build_headers → Authorization: Bearer … or Cookie: … for downstream tools
```

#### Hooks & multi-agent hints

| Hook | Role |
|------|------|
| `shannon-authorization-validator` | Blocks `shannon_exploit` without authorization string |
| `shannon-progress-tracker` | Phase timing + todo instructions |
| Post-tool escalation | High severity → Oracle; version strings → Librarian (CVE research) |

System prompt injects **~340 lines OWASP methodology** via `experimental.chat.system.transform`.

#### Strengths

1. **Provider agnostic** — Anthropic, OpenAI, Gemini, local models
2. **Rich auth/session layer** — multi-user IDOR testing
3. **Browser + logic testing** — Playwright scripts, rate-limit races
4. **Registration/login methodology** — explicit in system prompt
5. **Docker tool breadth** — sqlmap, nuclei, BrowserBruter, gowitness

#### Limitations

1. **Soft phases** — prompt-driven, not durable workflow state
2. **`shannon_exec` unconstrained** — flexible but less governed than GAE
3. **In-memory sessions** — lost on plugin restart (vs Shannon core `auth-state.json`)
4. **Stub tools not wired** — `shannon_logic_audit`, `shannon_cloud_recon` referenced but not registered
5. **No whitebox** — no code-path deny rules or repo deliverables
6. **No engagement graph** — findings not structured for cross-asset pivot queries

**Key files:**

- `src/index.ts` — plugin entry, tool registration
- `src/system-prompt.ts` — OWASP methodology
- `src/tools/shannon-auth-session/` — session manager
- `src/tools/shannon-browser/` — Playwright wrapper
- `src/tools/shannon-idor/` — IDOR auto/manual

---

### 2.3 Dark-Moon — MCP Gatekeeper + Multi-Agent Campaigns

**Location:** Not cloned in workspace; analysis from `Comparative Analysis/darkmoon_comp_analysis.html` and pentest reports.

#### Architecture (3 layers)

```
User (CLI/TUI/CI)
  → OpenCode container (18 agent markdown files + LLM)
    → FastMCP gatekeeper (toolbox container)
      → subprocess of allowlisted binaries ONLY
```

**Core principle:** AI **never gets a shell**. Only MCP functions.

#### Workflows (6 structured chains)

| Workflow | Tools chained | Output |
|----------|---------------|--------|
| `port_scan` | naabu → httpx | ports, HTTP services, tech |
| `vulnerability_scan` | nuclei | CVE findings |
| `subdomain_discovery` | subfinder → httpx | live subdomains |
| `web_crawler` | katana, waybackurls | URLs, forms, APIs |
| `ad_enumeration` | netexec, bloodhound-python | AD data |
| `kubernetes_audit` | kubescape, kubectl | K8s misconfigs |

#### Individual execution

`execute_command(tool, args)` — synchronous subprocess of **115 allowlisted tools**.

**Blocked:** `python3`, `node`, `npm` — no custom scripting through MCP.

#### Multi-agent dispatch (18 agents)

Signal → agent mapping (reactive, not scripted):

| Signal | Agent |
|--------|-------|
| WordPress stack | `wordpress` |
| GraphQL | `graphql` |
| Port 445 | `ad` |
| K8s API | `kubernetes` |
| React/Angular SPA | `headless-browser` |

- **Parallel dispatch** when multiple techs detected
- **Cascade depth cap: 3** (orchestrator → sub-agent → sub-sub-agent)
- Example: `pentest → wordpress → plugin reveals GraphQL → graphql`

#### Campaign lifecycle

```
PHASE 0: User flags (TARGET, FOCUS, EXCLUDE, CREDS, TOKEN, NOISE)
PHASE 1: Session + dashboard init
PHASE 2: Environmental discovery (workflows)
PHASE 3: Tech classification → agent dispatch
PHASE 4: Per-agent vuln discovery/exploitation
PHASE 5: Evidence findings → dashboard (EXPLOITED / CONFIRMED / UNCONFIRMED)
PHASE 6: Finalize
```

#### Strengths (highest “agentic behaviour” in samaa.tv comparison)

1. **True reactive orchestration** — LLM plans, dispatches, correlates
2. **Strongest MCP security boundary** — allowlist + no scripting
3. **Cross-asset reasoning** — caught 6 defaced subdomains on shared hosting
4. **WAF adaptation** — pivoted to `/index.php/` when blocked
5. **Live dashboard + CI/CD** — campaign API
6. **Evidence-tier findings** — request, payload, response required

#### Limitations

1. **Static 115-tool allowlist** — new tools need image rebuild
2. **No custom exploit scripts** — python/node blocked
3. **No binary exploitation** — no Ghidra/GDB/Pwntools
4. **Limited cloud** (beyond K8s) — no Prowler/Pacu
5. **Sync execution** — long scans block
6. **Weak exploitation follow-through** on samaa.tv — documented defacement, no active exploit
7. **Frontier model required** — $10–25+/scan; small models fail campaigns
8. **No signed authorization ledger** — scope via flags, not legal defensibility layer

---

### 2.4 HexStrike — Broadest CLI Integration Layer

**Location:** Harvested in `mcp-servers/` (upstream `Hexstrike/hexstrike-ai/` not in workspace).

#### Original architecture

```
LLM → hexstrike_mcp.py (150+ @mcp.tool)
  → HTTP → hexstrike_server.py (Flask, ~17k lines)
    → subprocess → JSON back to LLM
```

#### Harvested architecture (this repo)

```
LLM → mcp-servers/{category}/server.py (FastMCP)
  → tools/*.py run() → _core/runner.py → executor.py (shell=False)
```

**90 tools** across 10 categories — see `mcp-servers/README.md`.

#### Tool module contract

Every harvested tool:

```python
TOOL_NAME = "subfinder_scan"
def build_command(**params) -> str: ...  # CLI string
def run(...) -> dict: ...               # calls run_tool(use_recovery=True)
def parse(result) -> dict: ...          # mostly stub
```

**`additional_args`** on ~80+ tools — LLM escape hatch for any CLI flag.

#### Error recovery (lifted from upstream)

`mcp-servers/_core/error_handler.py`:

- `IntelligentErrorHandler` — classify errors, retry/backoff, param adjust
- `GracefulDegradation` — fallback chains (nmap→rustscan→masscan, subfinder→amass→dig)
- `RecoveryAction` — switch tool, escalate human, abort

**Caveat:** Docker exec path in your platform **bypasses** `run_tool()` recovery today.

#### Excluded from harvest (~60 entries)

- `optimize_tool_parameters_ai`, `select_optimal_tools_ai` — fake “AI brain”
- `execute_command`, file/process ops — server admin
- Bug bounty workflow wrappers
- Browser agent MCP

Real parameter intelligence = **external Commander LLM + `additional_args`**, not upstream heuristics.

#### Strengths

1. **Unmatched breadth** — recon through forensics, binary, exploit
2. **Uniform MCP interface** — `nuclei_scan(target=...)` without learning each CLI
3. **Battle-tested command recipes** — lifted from Flask routes
4. **Safe executor** — `shlex.split`, no shell
5. **Manual overrides** for complex tools — metasploit, pwntools, angr, gdb

#### Limitations

1. **No structured parsers** — agents get raw stdout
2. **Stateless** — no engagement graph inside MCP
3. **No orchestration** — tool list, not campaign brain
4. **Recovery not on primary docker path**
5. **Interactive tools awkward** — metasploit, gdb via MCP request/response
6. **Upstream “AI” was mostly dict lookup** — excluded intentionally

**Key files:**

- `scripts/harvest_hexstrike_tools.py` — generator
- `mcp-servers/_core/error_handler.py` — recovery
- `mcp-servers/_core/runner.py` — run loop
- `backend/src/pentest_platform/services/command_builder.py` — command-build bridge

---

## 3. Comparative Matrix

| Dimension | Shannon Core | Shannon Plugin | Dark-Moon | HexStrike | **Hybrid Target** |
|-----------|-------------|----------------|-----------|-----------|-------------------|
| Orchestration | Temporal (durable) | OpenCode LLM | OpenCode LLM | None (tool farm) | Temporal + Commander LLM |
| Tool count | SDK Bash + collectors | ~20 Docker tools | 115 allowlisted | 90 harvested | 90+ via GAE + capability tiers |
| LLM flag freedom | Broad bash | `shannon_exec` | Args only (allowlist) | `additional_args` | **`additional_args` + governed escape hatches** |
| Raw shell from LLM | Yes (Bash) | Yes (`shannon_exec`) | **No** | No | **No** (structured proposals) |
| Auth/session | Browser auth-state.json | `shannon_auth_session` | CREDS/TOKEN flags | hydra, netexec | **Unified session vault** |
| Browser/SPA | playwright-cli skill | Playwright scripts | headless-browser agent | (excluded browser agent) | **Dedicated browser capability** |
| Business logic | Prompt methodology | IDOR, rate-limit, upload | Agent markdown rules | Limited | **Logic capability + LLM freedom** |
| Token/JWT testing | vuln-auth agent | system-prompt + js_analyze | Agent constraints | jwt excluded | **auth capability module** |
| Exploit writing | exploit agents + Bash | shannon_exploit + exec | Limited (no python) | pwntools, msfvenom, metasploit | **Sandboxed exploit runner (gated)** |
| Binary analysis | via Bash | via exec | None | 15 binary tools | **binary.mcp category** |
| Cloud/K8s/AD | Limited | cloud stub | K8s + AD workflows | cloud category (12 tools) | **Full cloud + AD phases** |
| Findings rigor | Zod queues, confirmed | Report correlate | 3-tier evidence | Stub parse | **Shannon schema + graph** |
| Cross-asset pivot | Weak | Weak | **Strong** | Weak | **Engagement graph queries** |
| WAF bypass | Manual in prompts | Manual | **Automatic path pivot** | Retry only | **Escalation matrix** |
| Whitebox code | **Core strength** | None | None | None | **Optional `-r repo` phase** |
| Model lock-in | Claude SDK | None | None | None | **LiteLLM router** |
| Governance | Strong RoE | Exploit auth hook | MCP allowlist | Minimal | **All layers combined** |
| Cost control | Fixed phases | ReAct wander | Frontier $$$ | N/A | **Planner + Critic** |

---

## 4. Lessons From Real Campaigns (samaa.tv Pattern)

From `Comparative Analysis/all_compared_pentest_comparison.html` and `Tool_architecture.md`:

| Tool | What it did well | What it missed |
|------|------------------|----------------|
| **Dark-Moon** | 12 subdomains, **6 defaced on shared hosting**, WAF path pivot | No active exploit, weak CVSS/report |
| **Shannon** | Confirmed/unconfirmed, MITRE | 120+ subdomains but **missed live defacement** |
| **HexStrike** | `.env` leak found | No exploitation follow-through |
| **pentestMCP** | DB creds after manual restart | Didn't auto-pivot when WAF blocked |
| **Metasploit-MCP** | CVE reasoning | Missed defaced subdomains entirely |

**Design imperatives for hybrid:**

1. **Sister-domain / shared-hosting graph** — first-class query, not luck (Dark-Moon insight + Shannon graph discipline)
2. **Escalation on block** — automatic, not manual restart (pentestMCP failure mode)
3. **Exploitation follow-through** — finding → gated exploit attempt (HexStrike gap)
4. **Confirmed evidence rule** — PoC or exploitation proof (Shannon/XBOW principle)
5. **Cost-aware branch pruning** — failed exploits 5× expensive (research note in Tool_architecture.md)

---

## 5. Hybrid Architecture — Four Planes

Borrowed from `Tool_architecture.md`, instantiated with components from all four references:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PLANNING & REASONING PLANE                                              │
│  Commander (LiteLLM) · Planner · Critic · Tech-dispatch · Reflection    │
│  Task tree · Escalation matrix · Cost budget · Model-agnostic             │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ ToolCallProposal (never raw shell)
┌───────────────────────────────▼─────────────────────────────────────────┐
│  MEMORY & STATE PLANE                                                    │
│  Engagement graph · Findings store (→ Postgres) · Session/cred vault    │
│  Temporal workflows · Vector recall · Campaign dashboard                 │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  EXECUTION PLANE                                                         │
│  GAE bridge (command_builder, param_validator, mcp_client)              │
│  90 HexStrike tools · Capability tiers · Browser sandbox · Exploit sandbox│
│  Shannon-plugin-style auth helpers · Optional whitebox code MCP           │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│  GOVERNANCE PLANE                                                        │
│  Scope engine · Safety tiers · Impact approval gates · Audit ledger     │
│  Rate governor · Rollback log · Authorization contract reference         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Plane responsibilities

| Plane | From Shannon | From Plugin | From Dark-Moon | From HexStrike | Your GAE (done) |
|-------|-------------|-------------|----------------|----------------|-----------------|
| Planning | Temporal phases | OWASP prompt | Reactive dispatch | — | task_registry, skills |
| Memory | Deliverables, queues | — | Dashboard findings | — | findings_store |
| Execution | playwright-cli | auth, browser, IDOR | workflows | 90 tools | command_builder |
| Governance | RoE, scope lock | exploit auth hook | MCP allowlist | executor hardening | governance.py |

---

## 6. The Commander Model — LLM Chain Freedom

The Commander is **OpenCode** (external MCP client). It must exceed Dark-Moon’s flexibility while exceeding Dark-Moon’s safety.

### 6.1 What the LLM controls (full freedom)

| Decision | How |
|----------|-----|
| **Which tool** | Any registered tool OR capability-tier function |
| **Tool order** | Any chain — not fixed phases |
| **Typed params** | `domain`, `target`, `ports`, etc. |
| **Any CLI flags** | `additional_args` — **not whitelisted** |
| **Pivot timing** | After any finding, replan |
| **Multi-agent dispatch** | Spawn tech-specialist sub-agents (Dark-Moon pattern) |
| **Escalation** | Consult matrix on WAF/timeout/rate-limit |
| **Based on findings** | `based_on_findings: ["id1","id2"]` in proposal |

### 6.2 What the LLM cannot do (governance)

| Blocked | Why |
|---------|-----|
| Raw shell strings | Injection, audit, scope |
| Out-of-scope targets | Legal/safety |
| GATED tools without approval | responder, metasploit, etc. |
| Destructive actions (configurable) | Impact tiers |
| Shell metacharacters in args | `;|&`$()<>` |

### 6.3 Commander loop (pseudocode)

```python
async def commander_turn(engagement_id, run_id, user_message):
    catalog = GET(f"/capabilities/phases/{current_phase}/llm-catalog")
    skills = GET(f"/capabilities/skills/{current_phase}")
    memory = GET(f"/findings/summary?engagement_id={engagement_id}&run_id={run_id}")
    graph = GET(f"/engagements/{engagement_id}/graph/summary")  # future

    system = build_system_prompt(skills, catalog, memory, graph, escalation_matrix)

    # LiteLLM with structured output schema = ToolCallProposal
    proposal = await llm_structured(system, user_message, schema=ToolCallProposal)

    # Optional: Critic scores expected value vs cost before exec
    if critic.should_prune(proposal):
        return explain_skip_to_user(proposal)

    # 5-second override UX (shannon plugin pattern)
    await ui.preview_and_wait(proposal, timeout=5)

    validation = POST("/capabilities/validate", proposal)
    if not validation.approved:
        return retry_with_reason(validation.reason)

    result = POST("/mcp/execute", {
        **proposal,
        "engagement_id": engagement_id,
        "run_id": run_id,
    })

    # Reflection: did we cover expected checks for detected tech?
    reflection = await reflect_on_phase(detected_tech, new_findings)

    return format_response(result, new_findings, reflection)
```

### 6.4 Planner + Critic (fixes cost asymmetry)

From `Tool_architecture.md` §3:

- **Planner** maintains live task tree — branches spawn on findings (e.g. shared IP → sibling subdomain check)
- **Critic** scores branch: expected value vs token/request cost; prunes dead ends before 5× failed exploit cost

This is **not** in any reference tool today — it’s the hybrid differentiator.

---

## 7. Execution Layer — HexStrike + Governed Bridge

The recon/network execution foundation is built (see [`ARCHITECTURE.md`](./ARCHITECTURE.md)). Extend it:

### 7.1 Current GAE pipeline (keep)

```
ToolCallProposal → validate → command_builder → docker exec → parse → findings_store
```

### 7.2 Extensions needed

| Extension | Source pattern | Purpose |
|-----------|----------------|---------|
| Wire recovery on docker path | HexStrike `runner.py` | Auto-retry on timeout/rate-limit |
| Expand parsers | Shannon collectors | Structured findings for all major tools |
| Workflow MCP wrappers | Dark-Moon 6 workflows | Optional pre-chains (subfinder→httpx) |
| Capability tiers | Your task_registry | Expose 8 tasks not 90 tools to LLM |
| `governed_exec` escape | Shannon plugin `shannon_exec` but **structured** | Rare paths: custom curl/python **in sandbox** with proposal audit |

### 7.3 Governed escape hatch (beats Dark-Moon’s python block)

Dark-Moon blocks `python3` — limits custom PoC. Hybrid approach:

```python
class SandboxedScriptProposal(ToolCallProposal):
    tool_name: Literal["sandbox_run"]
    script_type: Literal["python", "curl_chain", "playwright"]
    script_body: str  # validated, no imports of os.system etc.
    reason: str
    impact_tier: Literal["read_only", "write", "destructive"]
```

- **read_only** — auto-approved (JWT decode scripts, timing tests)
- **write/destructive** — human approval gate
- Runs in **ephemeral container** with network scoped to target
- Full audit trail — beats raw `shannon_exec`

---

## 8. Identity & Auth Plane — Shannon Plugin Patterns

Port these capabilities as **first-class platform modules** (not OpenCode-only):

### 8.1 Session vault (upgrade from plugin in-memory)

| Feature | Plugin today | Hybrid target |
|---------|-------------|---------------|
| Create session | `shannon_auth_session` create | `POST /api/v1/sessions` |
| Login types | jwt, cookie, header | + API key, OAuth refresh, TOTP |
| Credentials | email/username + password | + manual JWT/cookies |
| Persistence | In-memory | **Postgres + encryption at rest** |
| Multi-user | Manual session IDs | Named personas: `user_a`, `user_b` for IDOR |
| Header builder | `build_headers` | Middleware on all web capability calls |

Implementation sketch:

```
backend/services/session_vault.py
backend/api/v1/endpoints/sessions.py
skills/shared/auth-testing.md
```

### 8.2 Registration & account lifecycle testing

From `shannon_plugin/.../system-prompt.ts`:

| Test class | Technique | Tool/capability |
|------------|-----------|-----------------|
| Role injection | `POST /register {"role":"admin"}` | `webapp` + browser |
| Stored XSS in email | iframe payloads in registration | browser capability |
| Account enumeration | duplicate email error messages | rate_limit_test pattern |
| Mass assignment | extra JSON fields on register | param_fuzz + LLM |
| OAuth weak patterns | reversed email btoa passwords | js_analyze + browser |

**Not a “register email service”** — it’s **methodology + session vault + browser** letting the LLM test any registration API.

### 8.3 Token/JWT testing capability

Combine:

- Shannon `vuln-auth` agent prompts (expiration, logout invalidation)
- Plugin `shannon_js_analyze` (token in localStorage)
- Custom `sandbox_run` scripts for alg:none, kid injection, claim tampering

Structured findings:

```python
Finding(finding_type=FindingType.OBSERVATION,
        title="JWT alg:none accepted",
        confidence=FindingConfidence.CONFIRMED,
        metadata={"technique": "token_bypass", "claim": "role"})
```

---

## 9. Browser & SPA Plane

### 9.1 Three browser modes (synthesis)

| Mode | Source | Use case |
|------|--------|----------|
| **CLI skill** | Shannon core `playwright-cli` | Fast authenticated flows, session reuse |
| **Script sandbox** | Plugin `shannon_browser` | Custom SPA routes, OAuth, DOM XSS verify |
| **Headless agent** | Dark-Moon `headless-browser` agent | Tech-dispatched when React/Angular detected |

### 9.2 Hybrid browser capability API

```json
{
  "tool_name": "browser_run",
  "params": {
    "mode": "playwright_script",
    "target": "https://app.example.com",
    "session_id": "sess_user_a"
  },
  "additional_args": "",
  "script": "await page.goto('/admin'); ..."
}
```

- Scripts stored in audit log
- Session cookies injected from vault
- Screenshots → findings evidence
- Beats HexStrike (excluded browser agent) and matches plugin depth

---

## 10. Business Logic & Token Bypass Testing

### 10.1 Logic testing (beats checklist tools)

Shannon plugin documents but **stub tools** exist (`shannon_logic_audit` not registered). Hybrid makes logic **a capability tier**, not a single tool:

**Task:** `business_logic_testing`

| Sub-capability | Implementation |
|----------------|----------------|
| Price/quantity tampering | LLM crafts requests; `webapp` tools + session vault |
| State machine bypass | LLM sequences (cart → checkout → paid without payment) |
| Race conditions | Port `shannon_rate_limit_test` race mode |
| IDOR | Port `shannon_idor_test` auto 17 patterns |
| Upload bypass | Port `shannon_upload_test` |
| Workflow abuse | Temporal-style state machine in engagement graph |

**LLM freedom:** No fixed checklist — skills suggest patterns; Commander chains freely.

### 10.2 Token bypass taxonomy (LLM-driven)

Skills file `skills/web/token-bypass.md` (to create):

```
1. JWT alg:none / key confusion / kid path traversal
2. Session fixation / predictable session IDs
3. OAuth redirect_uri manipulation
4. API key in JS bundle → privilege escalation
5. CSRF token reuse / missing on state-changing actions
6. Bearer token in URL/query params
7. GraphQL introspection → admin mutations without auth
```

Each technique: LLM picks tools + `additional_args` + optional `sandbox_run` script.

### 10.3 WAF / filter bypass (Dark-Moon + escalation matrix)

When `httpx` or `sqlmap` returns blocked:

```
1. Path pivot (/wp-json/ → /index.php/wp-json/)     [Dark-Moon samaa.tv]
2. Encoding variants (double URL encode, Unicode)     [LLM knowledge]
3. HTTP method tampering (GET→POST)                   [LLM + webapp tools]
4. Header smuggling (X-Forwarded-For, X-Original-URL) [additional_args]
5. Sister subdomain on same IP                        [graph query]
6. Switch tool (sqlmap → manual sandbox curl)         [escalation matrix]
```

Encode as **`config/escalation_matrix.yaml`** — first-class artifact the Planner consults.

---

## 11. Exploit Development & Post-Exploitation Plane

HexStrike provides **tools**; Shannon provides **exploit agent methodology**; Dark-Moon **stops short**. Hybrid adds structure:

### 11.1 Finding → exploit pipeline

```
Vuln finding (CWE/CVE/type)
  → exploit_planner.match(capability_registry)
  → ranked attempts with impact_tier
  → governance.check(each attempt)
  → execute (msfvenom / pwntools / metasploit / custom sandbox)
  → exploitation evidence finding (Shannon exploit-collector pattern)
```

### 11.2 Impact tiers (from Tool_architecture.md §6)

| Tier | Examples | Default gate |
|------|----------|--------------|
| **confirm_readonly** | SQLi boolean check, SSRF DNS callback | Auto |
| **confirm_write** | Create test file, insert row | Configurable auto |
| **exploit_rce** | webshell, reverse shell | Human approval |
| **postex** | credential dump, lateral movement | Human approval + RoE |

### 11.3 Exploit writing freedom (LLM + sandbox)

HexStrike tools:

- `pwntools_exploit` — generates Python exploit script
- `msfvenom_generate` — payload generation
- `metasploit_run` — module execution
- `angr_symbolic_execution`, `gdb_analyze`, `ropgadget_search` — binary chain

**Hybrid:** LLM writes exploit logic via:

1. **Structured tool calls** to binary/exploit MCP tools with `additional_args`
2. **`sandbox_run`** for custom pwntools/sploit scripts (gated)
3. **Shannon-style exploit agent** prompt for whitebox repos (optional `-r` mode)

Beats Dark-Moon (no python) and matches HexStrike breadth with **better governance than Shannon bash**.

### 11.4 Rollback ledger

Every state-changing action logged for cleanup — professional differentiator none of the four references do well.

---

## 12. Validation & Findings — Shannon Rigor

### 12.1 Finding schema (unified)

```yaml
finding:
  id: string
  title: string
  severity: critical|high|medium|low|info
  cvss_vector: string          # Dark-Moon gap
  cwe: string
  mitre_attack_id: string      # Shannon strength
  status: confirmed|unconfirmed|hypothesis|exploited  # Shannon + Dark-Moon
  confidence: confirmed|likely|hypothesis             # your schema
  endpoint: string
  discovered_by: agent|tool
  source_tool: string
  evidence:
    commands: []
    request: string            # Dark-Moon requirement
    response: string
    screenshots: []
  exploited: bool
  exploitation_evidence: string
  impact: string
  remediation: string
```

### 12.2 Confirmation rules (XBOW/Strix principle)

Mark **confirmed** only if:

- Reproducible PoC (command + response), OR
- Exploitation evidence (working shell, extracted data)

Mark **exploited** only with tier-appropriate proof.

### 12.3 Exploitation queues (from Shannon)

For whitebox mode, retain Shannon’s `*_exploitation_queue.json` pattern:

- Vuln agent produces structured queue
- Exploit agent consumes queue
- `exploit: false` → deterministic `findings-renderer` (no LLM)

Blackbox Commander mode uses `findings_store` instead — same confidence discipline.

---

## 13. Multi-Agent Dispatch — Dark-Moon Patterns

Port Dark-Moon’s **signal → specialist** model without 18 hardcoded markdown-only agents:

### 13.1 Tech dispatch table (config-driven)

```yaml
# config/tech_dispatch.yaml
signals:
  - match: { technology: wordpress }
    spawn_agents: [cms_wordpress]
    skills: [skills/cms/wordpress.md]
  - match: { port: 445 }
    spawn_agents: [smb_specialist]
    skills: [skills/network/smb-enumeration.md]
  - match: { technology: graphql }
    spawn_agents: [api_graphql]
  - match: { frontend: react|angular|vue }
    spawn_agents: [spa_browser]
```

Commander reads graph fingerprints → spawns sub-agents with **narrower tool catalog** (capability tier subset).

### 13.2 Cascade limit

Max depth 3 (Dark-Moon) — prevent infinite sub-agent loops.

### 13.3 Parallel dispatch

Multiple tech stacks detected → parallel sub-agents with isolated `run_id` suffixes.

---

## 14. Whitebox Code Analysis — Shannon Core

Optional engagement mode: `-r /path/to/repo`

| Shannon component | Hybrid integration |
|-------------------|-------------------|
| Pre-recon code agent | Temporal activity or Commander phase |
| Code path deny rules | Sync to SDK settings or block Read paths in sandbox |
| `@include` prompt partials | Your `skills_loader` pattern |
| Deliverables git checkpoints | Workspace per engagement |
| 5 OWASP parallel vuln agents | Configurable `vuln_classes` |

Blackbox engagements skip this plane entirely — **same platform, two modes**.

---

## 15. Escalation Matrix (WAF / Block / Dead-End)

First-class config (`config/escalation_matrix.yaml`):

```yaml
technique: sql_injection
blocked_signals: [waf_block, 403, cloudflare]
escalations:
  - action: alternate_path
    example: "/index.php/?id=1"
  - action: alternate_tool
    from: sqlmap_scan
    to: sandbox_run
    note: "manual boolean blind"
  - action: alternate_vector
    query: "graph.siblings_same_ip(target)"
  - action: encoding_variant
    llm_hint: "double URL encode, Unicode normalization"

technique: subdomain_enum
blocked_signals: [rate_limit]
escalations:
  - action: alternate_tool
    from: subfinder_scan
    to: amass_scan
    additional_args: "-passive"
  - action: adjust_params
    additional_args: "-t 2"
```

Planner **must** consult this before marking branch exhausted — fixes pentestMCP manual restart.

Integrate with HexStrike `GracefulDegradation.fallback_chains` for tool-level fallbacks.

---

## 16. Tool Surface Design — Not 90 Functions At Once

### 16.1 Three exposure tiers

| Tier | What LLM sees | Count |
|------|---------------|-------|
| **Task** | `subdomain_enumeration`, `port_discovery`, … | ~8–20 per phase |
| **Tool** | `subfinder_scan`, `rustscan_fast_scan`, … | ~24 recon+network (done) |
| **Full registry** | All 90 | Planner/admin only |

Dark-Moon exposes 115 tools — context overload. HexStrike upstream exposed 150+. **Hybrid uses tasks by default**, tools on drill-down.

### 16.2 Capability API (done)

`GET /api/v1/capabilities/phases/recon/llm-catalog`

### 16.3 Dynamic expansion

When Critic detects thin results:

```
"Few subdomains" → expand catalog to alternatives: amass, fierce, dnsenum
"Open 445" → inject smb_enumeration task into prompt
```

---

## 17. End-to-End Flow — Hybrid Campaign Example

**Target:** `example.com` (blackbox web + infra)

### Turn 1 — Commander recon

```
LLM → subfinder_scan(domain, additional_args="-all")
    → findings: 47 subdomains
LLM → httpx_probe(targets, additional_args="-td -sc -title")
    → findings: 12 live, tech: WordPress, Cloudflare
```

### Turn 2 — Graph pivot (beats Shannon checklist miss)

```
Graph query: subdomains on same IP as www.example.com
    → finds staging.example.com (shared hosting)
LLM → httpx_probe(staging) → defaced page detected
Finding: CRITICAL, status=confirmed, evidence=screenshot
```

### Turn 3 — Tech dispatch (Dark-Moon pattern)

```
Signal: WordPress → spawn cms_wordpress sub-agent
LLM → wpscan_analyze + waybackurls + wafw00f
WAF block on /wp-json/ → escalation_matrix → /index.php/wp-json/
    → user enumeration finding
```

### Turn 4 — Auth plane (plugin pattern)

```
LLM → session_create(user_a), session_create(user_b)
LLM → idor_test(mode=auto, auth_token=user_a, base_url=/api)
    → cross-user order access CONFIRMED
```

### Turn 5 — Logic + token (plugin + sandbox)

```
LLM → rate_limit_test(mode=race, endpoint=/api/checkout)
LLM → sandbox_run(script_type=python, read_only) # JWT alg:none test
    → token_bypass finding
```

### Turn 6 — Exploitation (gated)

```
Queue: SQLi hypothesis on /search?q=
LLM → sqlmap_scan(additional_args="--batch --level=2")
Governance: confirm_readonly tier → auto-approved
Finding: exploited=true, tier=confirm_readonly
```

### Turn 7 — Report

```
Shannon-style report agent OR shannon_report correlate
Output: CVSS + MITRE + exploitation evidence + rollback log
```

---

## 18. Implementation Roadmap

### Phase 0 — Done (your work)

- [x] GAE bridge: ToolCallProposal, command_builder, param_validator
- [x] 90-tool registry + MCP harvest
- [x] Recon/network task catalog + skills
- [x] Findings store + basic parsers
- [x] Capabilities + mcp + findings APIs

### Phase 1 — Commander foundation (OpenCode)

- [ ] LiteLLM router + structured ToolCallProposal output
- [ ] `POST /api/v1/agent/chat` loop
- [ ] Load catalog + skills + findings summary each turn
- [ ] 5-second override UX

### Phase 2 — Memory plane

- [ ] Postgres findings persistence
- [ ] Engagement graph (assets, relationships)
- [ ] Session/credential vault (port shannon_auth_session)
- [ ] Sister-domain / shared-IP graph queries

### Phase 3 — Escalation + Critic

- [ ] `config/escalation_matrix.yaml`
- [ ] Planner + Critic agents
- [ ] Wire HexStrike recovery on docker exec path
- [ ] Expand parsers (web, vuln, network)

### Phase 4 — Auth, browser, logic

- [ ] Session API + skills/auth-testing.md
- [ ] Browser capability (playwright sandbox)
- [ ] Port IDOR, rate-limit, upload tests from plugin
- [ ] `skills/web/token-bypass.md`, `skills/web/business-logic.md`

### Phase 5 — Workflows + dispatch

- [ ] Dark-Moon-style workflow wrappers (optional pre-chains)
- [ ] `config/tech_dispatch.yaml` + sub-agent spawning
- [ ] Web/cloud/binary capability tiers in YAML

### Phase 6 — Exploitation + governance

- [ ] Impact tier gates on exploit tools
- [ ] Sandboxed script runner (governed python)
- [ ] Rollback ledger
- [ ] Exploitation evidence in findings schema

### Phase 7 — Durable orchestration (optional whitebox)

- [ ] Temporal workflows (Shannon pattern) for long engagements
- [ ] Whitebox mode with `-r repo`
- [ ] Shannon collector pattern for deliverables

### Phase 8 — Hardening

- [ ] Model swap test (LiteLLM: Opus vs GPT vs local)
- [ ] Campaign replay from audit log
- [ ] CI/CD campaign API (Dark-Moon pattern)

---

## 19. Component status

> Historical note: this section once split work between two developers ("you vs friend"). That split is obsolete — **the Commander/brain is OpenCode** (an external MCP client), not a bespoke LiteLLM agent. The built-in agent loop still exists but is demoted. Current status:

| Component | Status |
|-----------|--------|
| HexStrike harvest + MCP servers | Done |
| command_builder, validator, governance hooks | Done (governance permissive — enforcement pending) |
| task_registry, skills (recon/network) | Done |
| findings_store, parsers | Done |
| MCP execute + hybrid memory APIs | Done |
| Engagement graph + evidence law + finalize | Done |
| Commander (OpenCode) driving via MCP | Done (primary path) |
| Built-in LiteLLM agent chat / Planner-Critic | Demoted (flag-off) |
| Session vault, browser/IDOR, escalation depth | Next |
| Killchain engine · exploit phase · Temporal durability | Later |

See [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md) for the authoritative status.

---

## 20. Appendix: Source Locations In This Workspace

| System | Path | Notes |
|--------|------|-------|
| Shannon core | `shannon/` (reference clone) | Temporal, agents, collectors |
| Shannon plugin | reference (see comparative analysis) | OpenCode, 20 tools |
| Dark-Moon | reference | See `Comparative Analysis/darkmoon_comp_analysis.html` |
| HexStrike harvest | `mcp-servers/` | ~90 tools |
| Our platform | repo root (`backend/`, `config/`, `skills/`, `platform-mcp/`) | Current build |
| Architecture (current) | `docs/ARCHITECTURE.md` | How it works today |
| Capability reference | `docs/CAPABILITY_REFERENCE.md` | Per-tool + memory model |
| Integration surface | `docs/INTEGRATION_CONTRACT.md` | MCP + HTTP APIs |
| Comparative analyses | `Comparative Analysis/*.html` | Reference-tool deep dives |
| Pentest reports | `Pentest-Reports/*.html` | Reference-tool outputs |

---

## Summary: Why This Hybrid Passes the Bar

| Requirement | How hybrid exceeds references |
|-------------|------------------------------|
| **LLM decides chain** | Commander + task tiers + full `additional_args` freedom |
| **Test business logic** | Plugin IDOR/race/upload patterns as capabilities + LLM chains |
| **Token bypasses** | Auth capability + sandbox scripts + skills taxonomy |
| **Write exploits** | HexStrike exploit/binary tools + gated sandbox + Shannon exploit agents |
| **Breadth** | 90 HexStrike tools vs plugin 20 vs Dark-Moon 115 allowlist |
| **Depth** | Shannon validation + exploitation evidence |
| **Exploration** | Dark-Moon dispatch + engagement graph |
| **Safety** | GAE proposals + governance + impact tiers (beats bash/exec) |
| **Durability** | Temporal option + Postgres memory |
| **Any model** | LiteLLM vs Claude lock-in |

The unbeatable platform is not one tool — it is **four planes** that let the LLM act like Dark-Moon’s explorer, report like Shannon, execute like HexStrike, and test auth/logic like the Shannon plugin — **without** exposing raw shell, **without** losing findings between turns, and **without** stopping at discovery when exploitation is authorized.

---

*Next recommended docs to create:* `config/escalation_matrix.yaml`, `skills/web/token-bypass.md`, `skills/web/business-logic.md`, `docs/SESSION_VAULT.md`
