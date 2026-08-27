# AI Pentesting Platform — Project Context

> **Purpose of this doc:** a single file that gives anyone (a coworker, a new
> contributor, or an AI assistant helping on this repo) enough context to be
> immediately useful — what this is, how it's built, how the pieces fit, and
> where things live. Paste this into a Claude Project's instructions, or hand
> it to a teammate as onboarding.

---

## 1. What this is, in one paragraph

An autonomous penetration-testing platform where an LLM is the brain and the
platform is the lab, referee, and shared memory. You point it at a domain, IP,
CIDR, or URL; it runs real Kali tools (nmap, subfinder, nuclei, sqlmap,
metasploit, a real headless browser, ~117 tools total) through a governed
execution kernel, parses output into typed findings, stores everything in a
durable per-engagement evidence graph in Postgres, and reports back — with
severity clamped to evidence quality so nothing is over-claimed. It works
**two ways at once**: as an MCP tool-surface for external coding-agent
harnesses (OpenCode, Claude Code) that bring their own LLM, and as a
**self-hosted conversational Commander** that runs on whatever LLM key you
configure (Claude, GPT, DeepSeek, Groq, or a free local Ollama model).

**The differentiator we're betting on:** typed, governed tools feeding a
durable, evidence-graded engagement graph — not raw shell access with
ephemeral memory (that's what generalist agent sandboxes like Strix do) and
not a tool surface with no brain of its own (that's what tool servers like
HexStrike do). We are structured findings + persistent memory + a real
brain, in one system.

---

## 2. Architecture — One Conductor, Two Executors

```
┌────────────────────────────┐        ┌──────────────────────────────────┐
│ Executor A: external        │        │ Executor B: the Commander        │
│ harness (OpenCode / Claude  │        │ (built-in, self-hosted)          │
│ Code / any MCP client)      │        │ chat via /api/v1/agent/chat[/stream]│
│ brings its own LLM + key    │        │ runs on ANY LiteLLM key you set  │
└──────────────┬───────────────┘       └───────────────┬──────────────────┘
               │ MCP (stdio)                            │ HTTP (same process)
               ▼                                        ▼
        platform-mcp/server.py                   phase_agent.py
        (~41 typed + control tools)               (phase="commander")
               │                                        │
               └───────────────────┬────────────────────┘
                                    ▼
              ┌─────────────────────────────────────────┐
              │   THE CONDUCTOR (LLM-free shared state)  │
              │   phase_supervisor.py + sufficiency.py   │
              │   - phase sequencing (recon always on;   │
              │     vuln/exploit unlock on evidence)     │
              │   - description-indexed skills, anchored │
              │     to the active phase                  │
              │   - the shared blackboard                │
              └───────────────────┬───────────────────────┘
                                    ▼
              ┌─────────────────────────────────────────┐
              │   ONE EXECUTION KERNEL                    │
              │   tool_execution.py                       │
              │   govern → validate → scan-budget →       │
              │   cache → build command → execute →       │
              │   parse → findings → ingest → graph →     │
              │   coverage → audit                        │
              └───────────┬───────────────────┬───────────┘
                          │ docker exec                │ SQL
                          ▼                             ▼
              ┌──────────────────────┐    ┌──────────────────────────┐
              │  ai-pentest-kali     │    │  Postgres                 │
              │  mcp-servers/*       │    │  engagements, runs,       │
              │  (nmap, subfinder,   │    │  findings, asset_nodes,   │
              │  nuclei, sqlmap,     │    │  asset_edges,             │
              │  metasploit, real    │    │  conversation_messages,   │
              │  Playwright browser) │    │  tool_coverage, ...       │
              └──────────────────────┘    └──────────────────────────┘
```

**Why two executors, and why it isn't a mess:** the conductor is a single
piece of LLM-free logic — phase sequencing, evidence thresholds, skill
surfacing, the blackboard. It decides *what/when*, never *how*, and never
calls an LLM itself. Both executors are just different *brains* driving the
exact same conductor and kernel, so their behavior can never diverge. They
are interchangeable, never concurrent, in one session.

- **Executor A** is free — bring your own harness and your own key.
- **Executor B** (the Commander) is the real self-hosted harness: a chat
  interface where you type free-form prompts exactly like you would in
  OpenCode, except the brain is *this platform's own* LLM loop. It owns the
  conductor as a **background job** — `launch_pipeline` starts the full
  recon→vuln→exploit run and returns immediately so the Commander stays
  conversational; you can steer it mid-run ("hit the sister domains harder"),
  check status, or stop it.

---

## 3. The execution kernel — what actually happens on a tool call

Every tool call, from either executor, goes through **one function**
(`tool_execution.execute_tool_request`) in this order:

1. **Resolve session** — engagement + run binding.
2. **Governance gate** — `GATED` (exploitation-tier) tools check
   `RulesOfEngagement.allow_exploitation`; `destructive` blast-radius calls
   need `destructive_actions_allowed`.
3. **Param validation + normalization** — canonical param shapes, apex
   canonicalization for per-domain probes.
4. **Pre-flight chunking** — a wide port range or huge host list is
   auto-split into job-store-managed chunks instead of one giant call.
5. **Scan-budget enforcement** — expensive full-range scans ask first unless
   `confirm_expensive=true`.
6. **Cache check** — identical tool+params+engagement is a cache hit.
7. **Execute** — via `docker exec` into the Kali tools container (or
   natively, if configured).
8. **Parse** — a registered parser (`services/parsers/*.py`) turns stdout
   into typed `Finding` objects with a `FindingConfidence` and
   `EvidenceGrade` — **severity is clamped by evidence quality**, so a
   passive Shodan port tag can never claim CRITICAL the way a confirmed
   exploit can.
9. **Ingest** — findings + graph edges write into Postgres
   (`findings_store`, `engagement_graph`).
10. **Auto-fallback** — on a clean failure (not a WAF/ban signal), the kernel
    automatically re-runs the top escalation once, so the LLM doesn't burn a
    turn on a dead end.
11. **Audit** — every call is logged.

This is why the platform's memory survives context limits and restarts: the
graph is the ground truth, not the chat transcript.

---

## 4. Skills — how methodology reaches the LLM

`skills/<phase>/*.md` are markdown files with YAML frontmatter:

```markdown
---
name: nuclei-scanning
description: Template-based vulnerability scanning with nuclei_scan against a live, tech-fingerprinted host; the default first vuln move.
phase: vuln
tags: [vuln, nuclei]
---
# Nuclei — template-based vulnerability scanning
...methodology...
```

- **One registry** (`knowledge_browser.py`) parses frontmatter for both
  executors — no divergent paths.
- **Phase-anchored surfacing**: the conductor knows the active phase and
  which downstream phases have unlocked (evidence thresholds met), and
  surfaces `name — description` for exactly those skills every turn. Full
  text is pulled on demand (`platform_skills` for Executor A, a `read_skill`
  control tool for Executor B) — so a relevant skill can't be missed, but the
  prompt never balloons with irrelevant methodology.
- **Custom skills are a zero-code drop-in**: add a file under `skills/<phase>/`
  (or `skills/custom/` with an explicit `phase:` field) with frontmatter, and
  it's indexed automatically, no restart or code change. See the README
  "Adding your own skills" section.
- Currently **66 skills** across recon, network, web, vuln, exploit, osint,
  commander, and shared (always-relevant methodology like evidence honesty,
  escalation playbooks, sister-domain discovery).

---

## 5. The Commander (Executor B) in detail

The Commander is a `phase="commander"` agent (same ReAct loop as every other
phase agent, reusing `phase_agent.py`) with:

- **The full tool catalog** — any registered tool, not phase-restricted.
- **Three control tools it alone gets**: `launch_pipeline` (start the
  conductor pipeline as a background asyncio task — never blocks the chat),
  `check_readiness` (phase status + running agents + recent conductor
  events), `stop_pipeline`.
- **Implicit target binding** — there is no `set_target` ceremony. Per-turn
  resolution: a target named in the message gets bound automatically; else
  the active conversation's engagement is reused; else one short clarifying
  question. This is `target_binding.py`.
- **Server-side conversation persistence** — one thread per engagement in
  Postgres (`conversation_messages` table), so the CLI and any future
  dashboard read/write the exact same history via
  `GET/DELETE /api/v1/agent/conversation/{engagement_id}`.
- **Any LLM key** — `POST /api/v1/config/llm` lets you switch model/key/base
  at runtime (writes to `.env`, hot-reloads). LiteLLM under the hood means
  Claude, GPT, Gemini, DeepSeek, Groq (free tier), or local Ollama all work
  identically. Local-first, single-user by design — no multi-tenant auth,
  because that's unneeded complexity for "the person running this sets their
  own key."

Entry point: `POST /api/v1/agent/chat` or `/chat/stream` (SSE — emits
`tool_start`/`tool_end`/`phase_triggered`/`pipeline_tick`/`assistant`/`done`
events live). `phase="full"` still exists as an explicit one-shot batch
pipeline call (not the chat default) for scriptable/CI use.

---

## 6. Repo map

```
AI-Pentesting-Tool/
├── backend/                    FastAPI app — the execution kernel + conductor + Commander
│   ├── src/pentest_platform/
│   │   ├── api/v1/endpoints/   REST + SSE endpoints (agent, engagements, findings, jobs, config, ...)
│   │   ├── services/           ~130 files: tool_execution (kernel), phase_agent, phase_supervisor
│   │   │                       (conductor), commander_pipeline, target_binding, conversation_store,
│   │   │                       knowledge_browser + skills_loader (skills registry), llm_service
│   │   │                       (LiteLLM), findings_store, engagement_graph, parsers/*
│   │   ├── models/              SQLAlchemy models (12 tables: engagements, findings, asset graph,
│   │   │                        conversation_messages, tool_coverage, exploit_candidates, ...)
│   │   ├── schemas/             Pydantic request/response + domain schemas
│   │   └── platform/            Executor-B-specific enrichment (adaptation, failure_analysis,
│   │                            handoff, situational_context)
│   ├── alembic/versions/        11 migrations (Postgres schema history)
│   └── tests/                   pytest suite
├── platform-mcp/                FastMCP server exposed to external harnesses (Executor A)
│   ├── server.py                 ~41 @mcp.tool() functions: platform_set_target, platform_context,
│   │                              platform_shell/script, platform_findings, platform_spawn_agent, ...
│   └── typed_*.py                Typed wrappers per tool family (recon, vuln, exploit, browser, osint)
├── mcp-servers/                  Tool implementations that run INSIDE the Kali container
│   ├── recon/ network/ vuln/ web/ exploit/ osint/ cloud/ binary/ forensics/ creds/ api/
│   │   (117 TOOL_NAME-registered tools: nmap, subfinder, amass, httpx, nuclei, sqlmap, dalfox,
│   │    metasploit, wpscan, browser_scrape/browser_flow (Playwright), theHarvester, ...)
│   └── _core/                    Shared runner/result plumbing every tool module uses
├── skills/                       66 markdown skills, YAML-frontmatter indexed (see §4)
│   ├── recon/ network/ web/ vuln/ exploit/ osint/ commander/ shared/ pipeline/ summary/ report/
├── cli/                          Terminal client (prompt_toolkit REPL + argparse `scan` subcommand)
│   ├── api/client.py              HTTP/SSE client — talks to backend only, no local intelligence
│   └── commands/slash.py          /scan /engage /findings /model /tools /reset etc.
├── config/                       YAML config: escalation_matrix, tool catalogs, parallelism, ...
├── docker-compose.yml            postgres + kali-tools + backend services
├── dashboards/                   (empty — GUI not yet built; backend is API-first and GUI-ready,
│                                   see §5's SSE + conversation + pipeline-activity endpoints)
├── strix/, hexstrike-ai/         Reference tools we studied (see §1) — not part of our product
├── RECON-GAPS-AND-IMPROVEMENTS.md  The strategic plan this codebase was audited/rebuilt against
└── docs/                          ARCHITECTURE.md, CAPABILITY_REFERENCE.md, DEVELOPER_GUIDE.md, ...
```

Rough size: **backend ~35K LOC**, **MCP surface (platform-mcp + mcp-servers)
~19K LOC**, **CLI ~1.7K LOC**, 66 skills, 117 registered tools, 12 DB tables.

---

## 7. Tech stack

| Layer | Choice |
|---|---|
| Backend API | FastAPI (Python), SQLAlchemy + Alembic, Postgres (SQLite fallback for tests) |
| LLM integration | LiteLLM — provider-agnostic (Claude/GPT/Gemini/DeepSeek/Groq/Ollama) |
| Tool execution sandbox | Docker container (`ai-pentest-kali`) with real Kali tools |
| MCP surface | FastMCP (stdio) for external harness integration |
| Browser automation | Playwright (headless Chromium) — session-aware, includes a built-in HTTP repeater |
| CLI | prompt_toolkit + httpx, talks to the backend over HTTP/SSE only |
| Streaming | Server-Sent Events (SSE) for live tool/agent progress |
| Frontend | Not yet built — deliberately deferred; backend is API-first so a dashboard is purely additive |

---

## 8. Design principles worth preserving

These came out of an architecture review and are load-bearing — violating
them is how this kind of project rots:

1. **New intelligence goes into the LLM-free conductor + description-indexed
   skills — never into a new per-executor service.** That's what keeps
   Executor A and Executor B from silently diverging.
2. **No forced-continuation gates.** We rejected "make the LLM keep going"
   mechanisms — they're unenforceable over MCP and duplicative on top of the
   evidence-based readiness signal. Trust the graph, not a nag.
3. **Advisory nudge text is a smell, not a feature.** We deleted a whole
   layer of "soft hints" bolted onto every tool response (memory-awareness
   notes, parallel-job suggestions, recovery hint text) because they
   duplicated what skills + phase-readiness already say once, in the right
   place, and just bloated every call. Keep *deterministic actions*
   (auto-fallback, auto-chunking); cut *advisory prose*.
3a. **Severity is earned from evidence, never asserted.** `EvidenceGrade`
   clamps `ClaimSeverity` — this is what keeps reports honest and is a real
   differentiator against noisy scanner output.
4. **API-first, GUI-ready, GUI not required.** Every capability a dashboard
   would need (SSE events, persisted conversation, pipeline-activity
   snapshot, key settings) already exists as a plain REST/SSE endpoint. The
   "proper GUI" is meant to be purely additive — a client of the existing
   surface, zero backend rewrite, when someone decides to build it.
5. **Local-first, single-user.** No multi-tenant auth. The person running
   the platform configures their own key. Don't add auth complexity without
   a concrete reason.
6. **Verify claims against code, not docs.** Docs drift; several were stale
   (e.g. claiming web/vuln/exploit were "planned" when their tools were
   already registered and wired). When in doubt, grep the code.

---

## 9. Where we stand vs. reference tools (for context, not competition)

| | Strix (agent sandbox) | HexStrike (tool server) | This platform |
|---|---|---|---|
| Brain | Is the brain (needs a paid key) | None — bring your own | Both: free via Executor A, any key (incl. free/local) via Executor B |
| Tool model | Raw shell + intercepting proxy, agent improvises | ~150 typed wrappers, no LLM loop | ~117 typed, governed tools + a shell/script escape hatch |
| Memory | Run-scoped notes, no durable graph | None (stateless) | Durable, evidence-graded engagement graph in Postgres |
| Web testing | Caido proxy for capture/replay | — | `browser_flow`: session-aware capture (headers+body) + a `replay` action (repeater reusing live auth cookies) + a live-DOM `snapshot` action |

We do not copy Strix's raw-shell design — throwing away the typed catalog +
durable graph would throw away the one thing that makes this elite instead of
noisy.

---

## 10. Quick links for people picking this up

- `README.md` — setup paths (Docker / lean Docker / fully local), CLI usage,
  MCP client configuration (OpenCode / Claude Desktop / ChatGPT Desktop),
  adding custom skills.
- `AGENTS.md` — the operator prompt/playbook an external harness (Executor A)
  is given; also a good read for understanding expected LLM behavior.
- `docs/ARCHITECTURE.md` — deeper architecture narrative with the
  four-conceptual-roles framing (Lab / Notebook / Referee / Brain).
- `docs/CAPABILITY_REFERENCE.md` — per-tool reference.
- `RECON-GAPS-AND-IMPROVEMENTS.md` — the strategic review/plan this
  architecture was most recently audited and extended against; useful
  history for *why* things are shaped this way.
