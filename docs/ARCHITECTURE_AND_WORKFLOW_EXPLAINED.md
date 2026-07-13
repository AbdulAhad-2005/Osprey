# Architecture & Workflow Explained

> **Audience:** Someone hearing about this platform for the first time — developers, operators, or stakeholders evaluating how our AI pentest agent works and *why* it is built this way.  
> **Scope:** Recon + network pipeline (current build). Web exploit, cloud, and binary phases are planned but not the focus here.  
> **Related:** [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md) · [`Hybrid_tools_workflow.md`](./Hybrid_tools_workflow.md) · [`LLM_INTEGRATION.md`](./LLM_INTEGRATION.md)

---

## Table of Contents

1. [The One-Sentence Idea](#1-the-one-sentence-idea)
2. [A Real Run — What Happened on scanme.nmap.org](#2-a-real-run--what-happened-on-scanmenmaporg)
3. [High-Level Architecture](#3-high-level-architecture)
4. [From Your Prompt to a Tool Command](#4-from-your-prompt-to-a-tool-command)
5. [The Layers — What Each Piece Does and Why](#5-the-layers--what-each-piece-does-and-why)
6. [Design Decisions: Our Way vs Alternatives](#6-design-decisions-our-way-vs-alternatives)
7. [What Other Big Pentest Tools Do at Each Stage](#7-what-other-big-pentest-tools-do-at-each-stage)
8. [Assist the LLM vs Force the LLM](#8-assist-the-llm-vs-force-the-llm)
9. [What Worked, What Failed, What We Fixed](#9-what-worked-what-failed-what-we-fixed)
10. [Glossary](#10-glossary)

---

## 1. The One-Sentence Idea

**You describe a target and a goal in plain English; an LLM chooses security tools from a governed catalog, runs them in Kali, reads the output, adapts, and reports back — while YAML skills and workflows *help* it, not *script* it.**

This is intentionally similar to how mature AI pentest products work: the model is the brain; the platform is the nervous system (tools, memory, safety, execution).

---

## 2. A Real Run — What Happened on scanme.nmap.org

Two successful sessions on `scanme.nmap.org` illustrate the design in practice.

### Run A — “Find live hosts and open ports”

| Turn | Tool | Result | Why it makes sense |
|------|------|--------|-------------------|
| 1 | `subfinder_scan` | OK | Passive subdomain enum — standard recon opener |
| 2 | `httpx_probe` | OK | Confirms HTTP live (`http://scanme.nmap.org`) |
| 3 | `nmap_service_scan` | OK | Version + scripts on open ports |
| 4 | *(no tool)* | Summary | Goal satisfied — agent stopped |

**~3 tools, ~63 seconds, 3/3 success.**

### Run B — “Complete recon for maximum visible surface”

| Turn | Tool | Result | Why it makes sense |
|------|------|--------|-------------------|
| 1 | `subfinder_scan` | OK | Subdomain / asset discovery |
| 2 | `waybackurls_discovery` | OK | Historical URLs from archives |
| 3 | `hakrawler_crawl` | OK | Light crawl of web surface |
| 4 | `nmap_custom_scan` (`-p- -sV -sC`) | **Timeout 300s** | Ambitious full-port + service scan — too slow in unprivileged container |
| 5 | `nmap_service_scan` (ports 22,80,9929,31337) | OK | **Adapted** — focused scan on known ports after failure |
| 6 | *(no tool)* | Summary | Broad surface documented |

**~5 tools, ~356 seconds, 4/5 success.**

### What this proves about the architecture

1. **The LLM chose different paths** for different prompts — not one fixed YAML script.
2. **It chained logically:** enum → archives → crawl → ports → services.
3. **It recovered from failure:** full `-p-` scan timed out; next turn used a targeted port list.
4. **It stopped when done** and offered sensible next steps (without brute-forcing a known test host).
5. **Follow-up questions** (“give me details”) used **conversation memory**, not new scans.

That is the intended behavior: **autonomous reasoning inside guardrails**, not “run all 23 tools.”

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  YOU (CLI or API)                                                            │
│  Natural language: "recon scanme.nmap.org — find live hosts and open ports" │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ POST /api/v1/agent/chat/stream (SSE)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AGENT LOOP (backend — agent_loop.py)                                        │
│  • Builds system prompt (rules + optional skill hints + target)              │
│  • Sends tool schemas to LiteLLM (Gemini, Groq, etc.)                        │
│  • ReAct loop: think → tool_call → read stdout/stderr → think → …           │
│  • Streams events: tool_start, tool_end, assistant, done                     │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ ToolExecutionRequest
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  EXECUTION PIPELINE (tool_execution.py)                                      │
│  Governance → param validate → command_builder → MCP/Kali → parse findings   │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ docker exec
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  KALI CONTAINER (ai-pentest-kali)                                             │
│  nmap, subfinder, httpx, waybackurls, hakrawler, …                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Four conceptual planes

| Plane | Purpose | Key files |
|-------|---------|-----------|
| **Commander (LLM)** | Reasoning, tool choice, summarization | `agent_loop.py`, `llm_service.py` |
| **Execution** | Safe command build + run | `command_builder.py`, `tool_execution.py`, `mcp_client.py` |
| **Memory** | Findings + engagement graph between turns | `findings_store.py`, `engagement_graph.py` |
| **Guidance** | Hints, not scripts | `skills/`, `config/recon_network_tools.yaml`, `config/workflows.yaml` |

We borrowed this split from analyzing **Shannon** (durable phases + validation), **Shannon OpenCode plugin** (LLM-as-orchestrator + Docker tools), **Dark-Moon** (reactive chaining + `additional_args`), and **HexStrike** (broad Kali tool surface) — then merged what each does best. See [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md) §2.

---

## 4. From Your Prompt to a Tool Command

Example: the LLM calls `httpx_probe` with `target=scanme.nmap.org`.

```
1. User prompt
      ↓
2. Target extraction (regex on prompt + engagement)
      → TARGET: scanme.nmap.org
      ↓
3. System prompt assembled
      → Autonomy rules + skill overviews + tool catalog (23 tools)
      ↓
4. LLM returns tool_call JSON
      → { "name": "httpx_probe", "arguments": { "target": "scanme.nmap.org" } }
      ↓
5. Governance check (scope, safety level, engagement ROE)
      ↓
6. param_validator (block shell metacharacters only)
      ↓
7. command_builder
      → Loads mcp-servers/recon/tools/httpx_probe.py build_command()
      → httpx -u scanme.nmap.org -t 50 -probe
      ↓
8. MCP client → docker exec in Kali
      ↓
9. stdout/stderr returned to LLM as tool result (truncated if huge)
      ↓
10. Parser → findings store (URLs, ports, techs)
      ↓
11. LLM next turn OR final summary
```

**Critical design choice:** the LLM never sends raw shell. It sends **structured tool calls**. The platform builds the CLI string. That is how we get **flexibility** (any flags via `additional_args`) without **arbitrary command injection**.

---

## 5. The Layers — What Each Piece Does and Why

### 5.1 Agent loop (`agent_loop.py`)

**What it does:** OpenCode-style ReAct — chat → tools → read output → repeat until the model answers in plain text or hits `max_agent_turns`.

**Why this way:**

| Choice | Reason |
|--------|--------|
| Simple loop, not Temporal | Faster to iterate; full durability (Shannon-style) can come later for 6-hour engagements |
| `use_recovery=False` on agent path | Avoids hybrid “escalation spam” confusing the model mid-run |
| Compact tool schemas | Keeps token use down for free-tier LLMs (Groq/Gemini limits) |
| Message pruning with Gemini-safe rules | Old tool output dropped without breaking “function call turn order” |
| SSE streaming to CLI | Operator sees live progress like OpenCode |

**What it does *not* do:** Execute `workflows.yaml` automatically. Workflows exist as **optional API actions**; the agent loop lets the LLM chain tools itself.

### 5.2 System prompt + skills

**Injected today:**

- Hard **boundaries** (recon/network only, no invented targets, read stderr and adapt)
- Short **phase overviews** from `skills/recon/phase-overview.md` and `skills/network/phase-overview.md`
- **Tool catalog** via function-calling schemas

**Not injected today:**

- Every individual skill file (e.g. `live-host-probing.md`) — keeps context small
- Full `workflows.yaml` text — would bias toward script-following

**Why:** Skills are **background knowledge**, explicitly labeled optional in the system prompt. The model’s training + live tool output matter more for ordering and flags.

### 5.3 Tool catalog (`config/recon_network_tools.yaml` + `task_registry.py`)

**What it does:** Defines ~24 recon/network tools: parameters, `llm_hints`, which task they belong to, and the free-form args field name (`additional_args`, `extra_args`, or `flags` for nmap).

**Why YAML + registry:**

| Alternative | Problem |
|-------------|---------|
| Hardcode tools in Python | Every new tool needs a code deploy |
| Give LLM 90 tools at once | Token explosion, bad tool choice |
| Allowlist every flag | Model can’t use `-Pn`, `--unprivileged`, etc. |

Our approach: **typed params + unrestricted `additional_args`** (only `;|&`$()<>` blocked).

### 5.4 Command builder (`command_builder.py` + `mcp-servers/*/tools/*.py`)

**What it does:** Harvested HexStrike `build_command()` functions per tool, plus nmap-specific logic in Python.

**Why two layers:**

- MCP modules match what actually runs in Kali (single source of truth for CLI shape)
- Central nmap builder adds container-aware defaults (`-sT -Pn --unprivileged` when SYN/raw sockets fail)

**Example fix we needed:** `httpx -l domain` treats the domain as a *file path*. Correct build is `httpx -u domain`. Without this layer, the LLM “reasoning” is irrelevant — every httpx call fails.

### 5.5 Governance (`governance.py`)

**What it does:** Blocks out-of-scope targets, gated tools without approval, engagement rules.

**Why:** Same reason commercial tools have ROE — autonomous ≠ unbounded. Shannon has preflight + scope lock; Dark-Moon has MCP gates; we have engagement + safety levels.

### 5.6 Findings store + parsers (`findings_store.py`, `parsers/recon_network.py`)

**What it does:** Parses subfinder, httpx, nmap, etc. stdout into structured findings; summarizes for later agent turns.

**Why:** Memory between turns. Without this, every prompt starts from zero. Dark-Moon and our hybrid blueprint both treat **structured memory** as first-class.

### 5.7 Workflows (`config/workflows.yaml` + `workflow_runner.py`)

**What it does:** Pre-defined multi-step chains, e.g. `subfinder → httpx` with specific default flags.

**Why optional:** Some runs benefit from one-click pipelines; others need the LLM to skip amass, add `-Pn`, or pivot to waybackurls (as in Run B). **Workflows help; they don’t replace the agent loop.**

### 5.8 CLI (`cli/`)

**What it does:** Interactive `pentest>` prompt, `/reset`, live SSE display of tool_start/tool_end.

**Why:** Operators need visibility. Black-box “wait 5 minutes” UX hides failures (rustscan missing, httpx wrong flag) and looks like the AI is “thinking” when tools are broken.

---

## 6. Design Decisions: Our Way vs Alternatives

### 6.1 LLM as orchestrator vs fixed pipeline

| Approach | Example | Pros | Cons |
|----------|---------|------|------|
| **Fixed pipeline** | Shannon core: pre-recon → recon → 5 vuln agents → report | Repeatable, auditable, resume-friendly | Rigid taxonomy; weak on novel pivots |
| **LLM orchestrator** | OpenCode Shannon plugin, **our agent loop** | Adapts to prompt, failures, target shape | Needs good tools + model; can loop on errors |
| **Pure script** | bash for-loop over tools | Predictable | No reasoning, no early stop, no summary |

**We chose LLM orchestrator** for the CLI agent path because the product goal is: *“recon this target like a senior pentester would”* — not *“always run steps 1–7.”*

Shannon’s pipeline is still the **reference for validation and reporting** when we add web/exploit phases later.

### 6.2 Structured tool calls vs raw Bash

| Approach | Example | Pros | Cons |
|----------|---------|------|------|
| **Raw Bash from LLM** | Shannon SDK `bypassPermissions` + Bash | Maximum flexibility | Hard to govern, audit, or parse |
| **Structured proposals** | `ToolCallProposal`, our function calling | Governable, parseable, repeatable | Must maintain tool catalog |
| **Escape hatch** | `shannon_exec` | Safety valve | Easy to abuse |

**We chose structured calls** + **`additional_args` for flags**. Same freedom as Bash for *scanning flags*, none of the injection risk for *shell metacharacters*.

### 6.3 Skills/workflows: hints vs mandatory

| Approach | Behavior |
|----------|----------|
| **Mandatory playbook** | Agent must follow YAML step order |
| **Hints only (ours)** | Phase overviews + llm_hints in catalog; LLM may ignore |
| **No guidance** | Model wanders or repeats tools |

**We chose hints** to match “help like big tools, don’t force.” Run B showed the model **going beyond** the minimal subdomain workflow (waybackurls, hakrawler) because the user asked for “complete recon” — that’s desirable.

### 6.4 Single execution pipeline

All paths — agent loop, `/mcp/execute`, workflows — go through **`tool_execution.py`**.

**Why:** One place for governance, validation, parsing, timeouts. Avoids “works in workflow but breaks in chat” drift.

### 6.5 Docker Kali sidecar

Tools run in **`ai-pentest-kali`**, not on the host.

**Why:** Reproducible tool versions, network capabilities (`NET_RAW` for future SYN), isolation. Same pattern as Shannon plugin’s `shannon-tools` container.

**Tradeoff:** Unprivileged nmap by default (no raw SYN without sudo). We encode that in `command_builder` so the LLM doesn’t have to guess container constraints every time.

### 6.6 Model agnostic via LiteLLM

**Why:** Groq for speed, Gemini for quota, Anthropic/OpenAI for quality — swap in `.env` without rewriting the agent. Shannon plugin and Dark-Moon both emphasize provider independence.

---

## 7. What Other Big Pentest Tools Do at Each Stage

Mapping **our Run B** to industry patterns:

| Stage | Our agent (Run B) | Shannon (core) | Shannon OpenCode plugin | Typical manual pentest |
|-------|-------------------|----------------|-------------------------|-------------------------|
| **Asset discovery** | `subfinder_scan` | Recon agent + collectors | `shannon_recon`, subfinder in container | subfinder, amass, crt.sh |
| **Historical URLs** | `waybackurls_discovery` | Recon deliverables | Crawlers / manual | waybackurls, gau |
| **Web surface** | `hakrawler_crawl` | Recon + browser | `shannon_crawler` | hakrawler, katana |
| **Live HTTP check** | *(skipped in B; used in Run A)* `httpx_probe` | HTTP checks in recon | httpx in recon wrapper | httpx, curl |
| **Port scan** | `nmap_custom_scan` → timeout → `nmap_service_scan` | Nmap via agent/bash | nmap in docker | rustscan → nmap |
| **Service ID** | `-sV -sC` via nmap tools | Same | Same | nmap scripts |
| **Summarize** | LLM markdown report | Report agent + templates | `shannon_report` | human write-up |

**Shannon core** would run this inside a **Temporal workflow** with fixed phase agents and Zod collectors — stronger **structure**, less **ad-hoc** ordering.

**OpenCode plugin** is closest to us: **LLM picks tools**, Docker runs them, system prompt carries methodology.

**Dark-Moon** adds heavier **dispatch/escalation** after each tool (`response.hybrid` hints) — we have that infrastructure but disabled recovery spam on the agent path for clarity.

---

## 8. Assist the LLM vs Force the LLM

This is the product philosophy you asked for — aligned with “other big pentest tools.”

### What “assist” means here

| Mechanism | Forces? | Assists how? |
|-----------|---------|--------------|
| Tool catalog (23 tools) | Can’t call tools outside catalog | Curated menu of real capabilities |
| Target guard | Can’t scan random invented domains | Prevents unsafe/hallucinated scope |
| Governance / ROE | Can’t run gated exploits without approval | Safety |
| Skill phase overviews | No | Suggests enum → live → ports chain |
| `llm_hints` per tool | No | “Run httpx after subfinder” |
| `workflows.yaml` | Only if API explicitly runs workflow | Optional accelerator |
| `command_builder` fixes | Can’t override with `-sS` if no root | Hides infra quirks from model |
| System prompt chain rule | Soft | “subdomains → live → ports → follow-up” |

### What “force” would look like (we deliberately avoid for the CLI agent)

- Auto-running `workflows.yaml` on every prompt
- Injecting full skill library (100+ pages) so model follows checklist
- Continuation nudges (“you must run 3 more tools”)
- Blocking LLM from stopping until every workflow step completes

### Verdict on your scanme runs

**Good for assist-not-force:**

- Run A: 3 tools, stopped when goal met  
- Run B: expanded surface (wayback, crawl) because *you asked*, not because YAML ran  
- Failure on `-p-` then **adapted** without human intervention  
- Honest summary (“don’t brute-force this test host”)

**Still assist layer improvements (not philosophy changes):**

- Surface findings summary to LLM mid-run more aggressively  
- Tool availability hints (rustscan not installed → suggest nmap)  
- Stronger default model tier for complex targets  
- Optional `--workflow suggest` mode that *offers* pipelines without executing them

---

## 9. What Worked, What Failed, What We Fixed

### Worked as designed

- Autonomous tool choice and ordering  
- Live SSE terminal UX  
- Gemini 3.x via LiteLLM  
- Target extraction and scope boundaries  
- Conversation memory on follow-ups  
- Structured summaries suitable for reporting  

### Failed due to infrastructure (not “dumb AI”)

| Symptom | Root cause | Fix applied |
|---------|------------|-------------|
| All tools fail loop | `httpx -l` used domain as file path | `httpx -u` in `httpx_probe.py` |
| nmap SYN always fails | No raw sockets in container | Default `-sT -Pn --unprivileged` in `command_builder.py` |
| rustscan exit 127 | Binary not installed in Kali image | Removed from agent tool list until installed |
| Gemini 400 mid-run | Message pruning broke turn order | Gemini-safe prune in `agent_loop.py` |
| Still on Groq after `.env` change | Docker container not recreated | Document `docker compose up -d --force-recreate backend` |
| `-p-` scan timeout | 65535 ports × unprivileged × 300s cap | Model adapted; platform could cap `-p-` or warn in llm_hints |

### Model tier note

`gemini-3.1-flash-lite` is fine for **scanme.nmap.org**-level recon. It loops more on **all-failure** scenarios than `gemini-3.5-flash`. Architecture is the same; **judgment quality** scales with model.

---

## 10. Glossary

| Term | Meaning |
|------|---------|
| **Agent loop** | ReAct cycle in `agent_loop.py` — LLM ↔ tools until done |
| **Commander** | The LLM role that plans and summarizes (vs execution layer) |
| **Tool catalog** | OpenAI-style function schemas built from `recon_network_tools.yaml` |
| **`additional_args`** | Free-form CLI flags the LLM attaches to any tool |
| **MCP / Kali bridge** | Backend spawns tool commands inside the Kali Docker container |
| **Findings store** | Parsed outputs (subdomains, ports, URLs) keyed by engagement/run |
| **Engagement graph** | Cross-asset relationships (host → port → service) for pivots |
| **Hybrid hints** | Escalation/dispatch suggestions on `response.hybrid` (optional on agent path) |
| **Workflow** | Multi-step YAML pipeline (optional); not the same as the agent loop |
| **GAE** | Governed Agentic Execution — structured proposals, no raw shell from LLM |
| **SSE stream** | Server-sent events for live CLI progress |

---

## Summary

We built a **hybrid autonomous recon platform** that:

1. **Helps** the LLM with tools, hints, memory, and safety — like Shannon, OpenCode, and Dark-Moon in spirit.  
2. **Does not force** rigid YAML scripts in the main CLI agent path — the model chooses order and stops when done.  
3. **Grounds** autonomy in real execution via Kali, command builders, and parsers — so reasoning connects to actual scan results.  

Your **scanme.nmap.org** runs are valid proof of the design: small tool chains, adaptation after timeout, readable reports, and different behavior for “quick ports” vs “complete surface” prompts — without running all 23 tools blindly.

For next depth: web phase agents (Shannon-style validation), optional workflow suggestions, durable Temporal runs for long engagements, and installing missing Kali tools (rustscan) or marking them unavailable at catalog load time.

---

*Document version: 2026-07-12 — reflects llmwork/AI-Pentesting-Tool recon+network agent path.*
