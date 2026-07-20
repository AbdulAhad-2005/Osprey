# Platform Improvement Plan — Freer LLM, Less Code, Full-Lifecycle Ready

> **Goal:** Keep our structural strengths (engagement memory, graph, soft gaps, gated execution) while fixing what Dark-Moon / Shannon / Shannon-plugin do better: **let the LLM think and execute what it thinks**, without exploding code as we grow past recon/network.
>
> **Work tree:** `llmwork/AI-Pentesting-Tool`  
> **Inputs:** `some_issues.docx`, Dark-Moon, Shannon Temporal, OpenCode Shannon plugin  
> **Principle:** *Advise hard, force soft. Thin exec path. Fat methodology in prompts/skills — not in Python per tool.*

---

## 1. What is actually wrong (honest diagnosis)

### 1.1 Your issues doc is largely correct

| Issue theme | Reality in our code |
|-------------|---------------------|
| Tool-centric, not LLM-centric | OpenCode may only call ~5 MCP tools; real work is `platform_exec(named_tool)` against a registry |
| Structured params feel rigid | `params_json` + schemas; freeform is only via `additional_args` (easy to miss / under-documented) |
| Hardcoded / brittle parsers | `parsers/recon_network.py` — known tools good; new tools / format drift fail silently |
| Escalation is pre-baked | YAML + HexStrike recovery + tech_dispatch all *suggest*; LLM is still nudged into a fixed menu |
| No creative scripting | No safe `exec` / shell escape hatch for one-liners or ad-hoc pipelines |
| Duplication | Target extract, nmap tool sets, validate/build, catalogs, agent vs MCP vs workflows |

### 1.2 What we do **better** than them (keep this)

| Strength | Why keep |
|----------|----------|
| Durable **engagement + run** isolation | Dark-Moon/plugin often lean on chat memory |
| **Graph + coverage gaps + attack-surface tree** | Soft memory spine others lack |
| Thin OpenCode façade (5 tools) | Right *shape*; wrong *payload freedom* |
| Governance / ROE gate | Safer than raw `shannon_exec` |

**Do not throw away the spine.** Fix the *restriction and duplication* around it.

### 1.3 What they do better for LLM reasoning

| System | Freedom model | Lesson |
|--------|---------------|--------|
| **Dark-Moon** | Allowlisted binary + **freeform CLI string**; reactive markdown agents | Gate *what*, free *how* |
| **Shannon Temporal** | Hard phases (when), free Claude SDK tools (how) | Coarse structure + free agent inside |
| **Shannon OpenCode plugin** | Many tools + **`shannon_exec` escape hatch**; skills as guidance | Highest freedom; thin wrappers |

**Freedom spectrum today:** Plugin ≫ Temporal-inside-phase ≈ Dark-Moon ≫ **Our Commander registry**

---

## 2. Target architecture (north star)

```
OpenCode (Commander — thinks freely)
    │
    ▼
platform-mcp  (thin + Shannon-level adaptability — no hardcoded lifecycle stages)
    ├─ platform_set_target / health / context(auto) / fanout
    ├─ platform_exec(tool, params, additional_args)   ← registered wrappers
    ├─ platform_shell(command)                        ← single allowlisted argv
    └─ platform_script(code, language)                ← write→run (join/logic/HTTP)
    │
    ▼
ONE execute kernel  (tool_execution + shell_exec + script_exec)
    ├─ session bind (engagement isolation)
    ├─ governance / ROE where registered tools apply
    ├─ script: file under /tmp/pentest/<engagement>/ then interpreter argv
    ├─ ALWAYS store raw stdout/stderr (observation fallback)
    ├─ best-effort structured parse — never block on parse miss
    └─ soft hints: gaps + inferred_focus (advisory)
```

**Status:** Adaptive context + three exec lanes (exec/shell/script). Expand recon→network→later via skills + scripts, not stage enums.

**Demote parallel brains (done via flags):**

- LiteLLM orchestrator — `ENABLE_BUILTIN_AGENT=false` (default)
- YAML workflow runner — `ENABLE_WORKFLOWS=false` (default)
- Duplicate catalogs — still TODO (single source later)

---

```
```
```
## 3. Make the LLM freer (without becoming unsafe)

### 3.1 Widen the payload, not the MCP tool count

Keep ~5–6 MCP tools. Change what `exec` means:

| Mode | LLM says | Backend does |
|------|----------|--------------|
| **Named tool** | `platform_exec("httpx_probe", {...}, additional_args="-sc -td")` | Validate lightly + build from module |
| **Allowlisted shell** | `platform_shell("nmap -sV -p 80,443 1.2.3.4", reason="service enum on live IP")` | Parse argv, check binary ∈ allowlist, scope check target tokens, run list-exec |

This is Dark-Moon’s model: **gatekeeper + freeform command**, not one Python function per Kali flag.

### 3.2 Treat `additional_args` as first-class

Today freeform exists but feels second-class. Fix:

- Document in `AGENTS.md`: “Prefer `additional_args` for any valid flags.”
- Stop over-normalizing away creative flags in `command_builder` / `agent_arg_normalizer`.
- Catalog hints = examples, not cages.

### 3.3 Soft methodology, hard safety

| Soft (LLM may ignore) | Hard (backend refuses) |
|-----------------------|-------------------------|
| 8-stage pipeline skills | Out-of-scope targets |
| Coverage gaps | Shell metacharacters / injection |
| Escalation suggestions | Gated exploit without approval |
| Tech dispatch | Destructive tools without ROE |
| Attack-surface tree | Fan-out without confirm |

Align with Shannon plugin: **prompt + skills steer; hooks/gates block dangerous acts.**

### 3.4 Parsing: never starve the LLM

From your doc — biggest decision-quality bug:

1. **Always persist raw stdout/stderr** (even on failure / timeout).
2. Structured parsers = best-effort enrichment.
3. Add `platform_query_output` or include truncated raw in context so LLM can re-read.
4. Optional later: LLM-assisted parse for unknown tools (async, not on critical path).

**Rule:** Parse miss ≠ “nothing found.”

### 3.5 Phase model must be open

Replace hard `recon | network | full` with:

```
phase ∈ categories from catalog
  e.g. recon | network | web | vuln | exploit | postex | report | …
```

- `platform_context(phase="web")` loads `skills/web/*` + relevant tools only  
- Coverage engines become **plugins per domain** (attack-surface for recon; vuln coverage later)  
- Don’t rewrite `commander_context` for every new phase — register loaders

---

## 4. Kill redundancy (code weight)

### 4.1 One execute path

```
KEEP:  platform-mcp → tool_execution
DEMOTE: agent.py / orchestrator / phase_agent / agent_assist   (feature flag)
DEMOTE: workflow_runner + workflows.yaml                      (optional API only)
DELETE: dead tool_runner.py, duplicate stubs
```

### 4.2 One catalog

**Today:** `tool_registry.py` + `recon_network_tools.yaml` + MCP modules + `tool_discovery` schemas.

**Target:**

1. MCP tool modules = **source of truth** for `build_command` / executable  
2. Auto-generate registry summary at startup (name, category, safety, params hints)  
3. One YAML overlay for LLM hints / defaults only (`config/tools.yaml`) — not a second full catalog  
4. Skills reference tool **names**, not re-declare them

### 4.3 One command builder

- CLI assembly lives in `mcp-servers/<cat>/tools/*.py` only  
- Backend `command_builder` becomes a thin caller + preview  
- Remove duplicated `_NMAP_TOOLS` sets / special cases in multiple files  

### 4.4 One failure advisor

Merge competing layers into **one** soft channel:

| Keep | Fold / remove |
|------|----------------|
| Coverage gaps + graph pivots (primary) | Triple-stack: HexStrike recovery + escalation_matrix + tech_dispatch all in every context |
| Optional: one escalation YAML | `recovery_bridge` dual-path; dump full playbook every turn |

### 4.5 Slim context packets

`platform_context` today dumps entire phase skill folders + catalog + playbook + gaps + tree.

**Target packet:**

1. Session header (target, engagement, run)  
2. Condensed findings summary  
3. Attack-surface / network (or phase) surface  
4. Top N coverage gaps  
5. **Short** role guidance (commander overview only)  
6. Available tool **names** (not full schemas) — load schema on demand  

Skills load **on demand** when LLM picks a task, not every turn.

### 4.6 Shared utilities (real DRY)

Create a small shared module (backend only — don’t invent a giant `shared/` mega-package):

| Utility | Consolidate from |
|---------|------------------|
| `extract_target(params)` | tool_execution, command_builder, validators |
| `normalize_domain(raw)` | platform-mcp + session_context |
| `safe_json_loads` | MCP + endpoints |
| Allowlist sets | one constants module |

---

## 5. Adaptable full platform (not recon/network-only)

### 5.1 Layer cake that scales

| Layer | Recon/net today | Web/vuln later | How it extends |
|-------|-----------------|----------------|----------------|
| MCP façade | same 5–6 tools | same | No new MCP tools per phase |
| Execute kernel | same | same | Allowlist grows |
| Memory | findings + graph | + vuln findings types | Schema already flexible (`tags`, `extra`) |
| Surfaces | attack-surface tree, network surface | e.g. app-route surface, vuln coverage | New *surface plugins* |
| Skills | `skills/recon`, `network` | `skills/web`, `vuln`, `exploit` | Markdown only |
| Parsers | `recon_network.py` | `web.py`, `vuln.py` | Registry plugins |
| Agents (optional) | Commander only | Specialist prompts like Dark-Moon | Prompt files, not new services |

### 5.2 What we refuse to do as we grow

- ❌ One new Python service per OWASP category  
- ❌ One MCP tool per Kali binary flag  
- ❌ Hard-coded phase enums forever  
- ❌ Require a perfect parser before a tool is “usable”  
- ❌ Keep LiteLLM agent + OpenCode + workflows all “primary”

### 5.3 What we allow as we grow

- ✅ New skill markdown + allowlist entry  
- ✅ Optional parser for structured memory quality  
- ✅ New coverage/surface module registered in context builder  
- ✅ Specialist “agent” prompts (CMS, AD, API) that still call the same `platform_exec` / `platform_shell`

---

## 6. Phased delivery (practical FYP roadmap)

### Phase X0 — Hygiene (1–2 days)

- Delete dead code (`tool_runner`, duplicate stubs)  
- Feature-flag LiteLLM agent + workflows off by default  
- Always store raw tool output  
- Document `additional_args` as first-class in `AGENTS.md`

### Phase X1 — Freedom (3–5 days)

- Add gated `platform_shell` (allowlist + argv + scope)  
- Slim `platform_context` packet  
- Stop dumping full skill trees every turn  

### Phase X2 — Consolidate catalogs (3–5 days)

- Generate tool list from MCP modules  
- Single `config/tools.yaml` overlay  
- Thin `command_builder`  

### Phase X3 — Parsing resilience (ongoing)

- Parser registry with fallback “raw observation” finding  
- Parse stderr too  
- Confidence + `parser_source` on findings  

### Phase X4 — Open phases (before vuln work)

- Open phase enum / category-driven context  
- Add `skills/web` or `vuln` skeleton  
- Coverage plugin interface  

### Phase X5 — Specialist prompts (optional)

- Dark-Moon-style reactive specialist skills (API, CMS, auth)  
- Still one execute kernel  

---

## 7. Design decisions (explicit)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Keep 5-tool MCP façade? | **Yes** | Matches OpenCode; reduces cognitive load |
| Add raw shell? | **Yes, gated** | Unlocks think→execute like plugin/Dark-Moon |
| Force Temporal-like phases? | **No (for now)** | Soft phases + skills; Temporal later if resume/durability needed |
| LLM parses all output? | **Fallback only** | Cost/latency; deterministic parsers first |
| Parallel agent backends? | **One primary (OpenCode)** | Code weight |
| Market/title language | Platform/framework for **full lifecycle**, not “recon tool” | Docs must stop saying recon/network-only |

---

## 8. Success metrics

| Metric | Today | Target |
|--------|-------|--------|
| Paths that can run a tool | 3 (MCP, agent, workflow) | **1 primary** |
| Places that define “valid tools” | 3–4 | **1 generated + 1 YAML hints** |
| Soft-hint systems in context | 3+ | **1 primary** |
| LLM blocked without registry tool | Always | Can use **allowlisted shell** |
| New phase cost | New enums + YAML + services | Skills + allowlist + optional parser |
| Parse miss → empty memory | Common | Raw always stored; observation fallback |

---

## 9. Summary for you / mam

**Problem:** Architecture is strong on memory and safety, but **over-codes the LLM’s hands** (registry-only exec, brittle parsers, recon/network hardcoding) and **duplicates brains** (agent + workflows + MCP).

**Direction:** Become more like Dark-Moon/Shannon-plugin on *freedom* (allowlisted freeform + skills), keep our *spine* (engagements, graph, gaps), and become more like Shannon Temporal only where we need durable phases later — not as a code explosion today.

**One line:**  
*Thin gatekeeper, free thinker, durable memory, open phases — methodology in markdown, not in duplicated Python.*

---

## 10. Next implementation step (recommended)

Start with **X0 + X1**:

1. Quarantine parallel agent/workflow paths  
2. Persist raw output always  
3. Add `platform_shell` with allowlist  
4. Slim context  

That alone makes the LLM feel “Shannon-like” while keeping your FYP differentiator (graph memory + soft coverage).
