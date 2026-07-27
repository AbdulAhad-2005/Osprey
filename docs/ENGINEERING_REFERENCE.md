# Engineering Reference — How This Platform Actually Works

**Purpose of this document.** You've mostly vibe-coded this app: you ask an AI to fix or add
something, it does, and you don't have an independent way to check whether the change was good,
whether it silently broke something else, or why the LLM operator behaved a certain way. This
document is not a redundancy audit and not a to-do list — it's the mental model you need so that
*you* can read a diff, read a log line, or watch the agent misbehave and know **where in the
system to look**. Every claim below is traced to a real file/function I read directly in this
codebase on 2026-07-24 (not inferred from docs, which — as you know — can go stale).

Read it once top to bottom to build the map. After that, use it as a lookup: find the symptom in
§7 (Debugging Playbook) or the component in §4 (Component Reference) and jump there.

---

## Table of contents

1. [The three planes, in one picture](#1-the-three-planes-in-one-picture)
2. [Full request lifecycle, traced](#2-full-request-lifecycle-traced)
3. [The tool contract — three layers you must not confuse](#3-the-tool-contract--three-layers-you-must-not-confuse)
4. [Component reference](#4-component-reference)
5. [The LLM/agent contract — why the model behaves the way it does](#5-the-llmagent-contract)
6. [Config-driven behavior map](#6-config-driven-behavior-map)
7. [Debugging playbook — symptom → where to look](#7-debugging-playbook)
8. [Latency map — where time actually goes](#8-latency-map--where-time-actually-goes)
9. [Persistence map — what survives a restart and what doesn't](#9-persistence-map)
10. [How to verify an AI-made change yourself](#10-how-to-verify-an-ai-made-change-yourself)
11. [Extension points — adding a new tool / category / phase](#11-extension-points)
12. [File index — one-line purpose for every service](#12-file-index)

---

## 1. The three planes, in one picture

```
┌───────────────────────────────────────────────────────────────────────┐
│  OPERATOR (two possible front ends — pick one per session)            │
│  A) OpenCode / Claude Desktop / ChatGPT ──MCP stdio──▶ platform-mcp/  │
│     server.py (~35 platform_* tools, driven by AGENTS.md)             │
│  B) Backend's own CLI/chat loop ──▶ agent_loop.py (recon+network only)│
└───────────────────────────┬───────────────────────────────────────────┘
                            │ HTTP (localhost:9000/api/v1/...)
┌───────────────────────────▼───────────────────────────────────────────┐
│  CONTROL PLANE — FastAPI backend (backend/src/pentest_platform/)      │
│  api/v1/endpoints/*  →  services/tool_execution.py (THE pipeline)     │
│  governance → validate → scan_budget → cache → command_builder        │
│  → mcp_client → summarize → ingest → graph → coverage → recovery      │
└───────────────────────────┬───────────────────────────────────────────┘
                            │ docker exec -i ai-pentest-kali bash -c "<cmd>"
┌───────────────────────────▼───────────────────────────────────────────┐
│  EXECUTION PLANE — kali-tools container                               │
│  mcp-servers/<category>/tools/<tool>.py — build_command() + parse()   │
│  Real binaries: nmap, subfinder, httpx, nuclei, sqlmap, ... (90+)     │
└─────────────────────────────────────────────────────────────────────┘
```

Two things to internalize immediately because they explain a lot of "why did this happen":

- **There are two separate operator loops** (A and B above) that share the same backend and tool
  catalog but have **different system prompts, different tool-filtering, different max-turns**.
  If you're debugging "the agent did something weird," first establish *which* front end produced
  it — the fix location is different for each.
- **The MCP protocol (JSON-RPC over stdio) is not actually used in your real deployment.** See §3.

---

## 2. Full request lifecycle, traced

This is the walk every tool call takes in the production (docker-compose) setup, file by file.
Use this section when something breaks and you don't know which of the ~15 steps ate the bug.

**Entry points** (either path lands on the same pipeline):
- MCP path: `platform-mcp/server.py` → a `@mcp.tool()` function (e.g. `platform_exec`, or a typed
  action tool like `nmap_syn_scan`) → HTTP POST to `backend`'s `/api/v1/mcp/execute`.
- Built-in CLI path: `agent_loop.py::_execute_tool` → calls `execute_tool_request()` **in-process**
  (no HTTP hop — it's the same Python process).

Both converge on **`execute_tool_request()`** in
[`backend/src/pentest_platform/services/tool_execution.py`](../backend/src/pentest_platform/services/tool_execution.py):

1. **Tool lookup** (`get_tool_definition`) — if the name isn't in the 879-line catalog in
   `tool_registry.py`, you get a 404 with fuzzy-match suggestions. *(This is the #1 cause of
   "the LLM tried a tool that doesn't exist" — the catalog is the single source of truth for
   valid names, not the folders under `mcp-servers/`.)*
2. **Session resolution** (`session_context.py`) — resolves/creates the `engagement_id` (one per
   target domain, reused across runs — `get_latest_by_target`) and the `run_id` (one per
   conversation/session). **A new engagement is silently created** if the target doesn't match any
   existing one — this is why re-running against the same domain sometimes "remembers" things and
   sometimes doesn't: it depends on whether `normalize_target()` produced the same string.
3. **Governance check** (`governance.py`) — **currently a no-op**. It always returns `approved=True`.
   Historically it blocked out-of-scope targets; that was deliberately disabled (see the file's
   own docstring) because it blocked legitimate pivots. If you ever see "governance_decision" in a
   response, know that it cannot currently block anything — don't waste time debugging it as a gate.
4. **Param validation** (`param_validator.py`) — this is the *real* gate. It does three things:
   blocks shell metacharacters `;|&`$()<>` in any string param or in `additional_args` (this is
   your entire injection defense — simple and intentional, not a bug); normalizes aliases
   (`domain`/`host`/`url` all map to the tool's real primary param via
   `agent_arg_normalizer.py`); and **rejects the call outright if the primary target param is
   empty** — this is a common silent failure: the LLM calls a tool with the wrong param name, gets
   a 400, and you see "it failed" without an obvious reason unless you read `validation.reason`.
5. **Scan budget gate** (`scan_budget.py`) — blocks full port ranges (`-p-`, `1-65535`, or spans
   >2000 ports) unless `confirm_expensive=true` is set. This is a deliberate throttle from your
   "never do a full port scan, it times out" rule — it raises `ValueError` → HTTP 400. If a scan
   you expect to run silently doesn't, check here before assuming the tool is broken.
6. **Cache check** (`exec_cache.py`) — key = sha256(engagement_id + tool_name + normalized params +
   additional_args), TTL 1 hour, in-process dict (not Postgres — dies on backend restart). **A
   cache hit returns the old result verbatim** with `cache_hit=true` and a hint telling the LLM to
   pass `force_refresh=true`. If you changed a tool's behavior and re-ran it and got the *old*
   output, this is why — it's not the tool, it's the cache.
7. **Command building** (`command_builder.py::build_command_for_tool`) — see §3, this is the part
   most likely to confuse you when adding tools.
8. **Execution** (`mcp_client.py::call_tool` → `_call_via_docker_exec`) — spawns
   `docker exec -i ai-pentest-kali bash -c "<command>"` from the **backend container itself**,
   using the docker socket mounted in (`/var/run/docker.sock`). Captures stdout (capped 50,000
   chars) and stderr (capped 10,000 chars) from that single process. **`duration_seconds` is hardcoded
   to `0` on this path** — it is not measured. If you're trying to profile which tool is slow, this
   field will lie to you; time it externally (wall clock around the call, or the job's
   `started_at`/`finished_at` in `job_store.py`).
9. **Parsing** — the tool's own `parse()` function (dynamically imported from
   `mcp-servers/<category>/tools/<tool>.py`) turns raw stdout into a structured dict. If a tool has
   no `parse()` or it throws, this is swallowed (`except Exception: logger.debug(...)`) and
   `parsed` stays `{}` — raw stdout is still returned, so nothing is lost to the LLM, but nothing
   structured is available either.
10. **Findings ingest** (`summarize_execution` + `ingest_promoter.apply_ingest_rules`) — every tool
    run, success or failure, gets an observation persisted (`force_raw_observation=True`), plus
    whatever the regex rules in `config/ingest_rules.yaml` match (subdomains, ports, tech
    fingerprints, SPA/API demotion signals, etc.). This is genuinely universal — it runs for *any*
    tool's stdout, not per-tool logic.
11. **Stdout indexing** (`artifacts.py` + `stdout_index.py`) — full stdout is written to a text
    artifact file and indexed with a path + 800-char snippet, so `platform_artifact` can fetch the
    complete original output later even if the structured parse missed something.
12. **Tool coverage recording** (`tool_coverage_store.py`) — marks "this tool ran against this
    asset" for the surface-expansion heuristics in `hypothesis_engine.py` to know what hasn't been
    tried yet.
13. **Recovery / escalation** (`_build_hybrid_meta`) — only computed when the call failed, timed
    out, or succeeded with **empty** stdout (`empty_success`). Pulls: static fallback chain
    (`_STATIC_FALLBACKS` dict at the top of `tool_execution.py`), `escalation_registry.py`
    suggestions, `tech_dispatch.py` suggestions, and graph pivot hints (siblings on the same IP).
    These are all advisory strings attached to `response.hybrid` / `response.next_hint` — nothing
    here forces the LLM to do anything.
14. **Audit log** (`audit_log.py`) — appended **in memory only** (see §9). Gone on restart.
15. **Response returned** up through whichever entry point started the call.

If you take away one thing from this section: **steps 3–6 are the four places a call can be
silently altered or blocked before the tool even runs**, and none of them show up as "the tool
failed" — they show up as HTTP 400s or cache hits. When something "doesn't work," check these
four before assuming the tool binary or the LLM is at fault.

---

## 3. The tool contract — three layers you must not confuse

This is the part of the codebase most likely to bite you when you (or an AI) add a new tool,
because there are **three separate places** a tool's identity lives, and they can drift out of
sync silently.

**Layer 1 — the catalog** (`backend/src/pentest_platform/services/tool_registry.py`, 879 lines).
A giant hand-written list of `ToolDefinition` entries — one per tool, with name, category, safety
level, description (this description is what the LLM sees as the tool's docstring/schema), and
typed parameter specs. **This is the only place that decides whether a tool name is "known."**
Adding a Python file under `mcp-servers/` without adding an entry here means the tool is
unreachable — `get_tool_definition()` returns `None` and every call 404s.

**Layer 2 — the adapter module** (`mcp-servers/<category>/tools/<tool_name>.py`). Each file
exposes two functions: `build_command(**params) -> str` (turns typed params into a CLI string) and
`parse(tool_result) -> dict` (turns raw stdout into structured data, using `_core/result.py`'s
`ToolResult` shape). These are **dynamically imported by file path** at call time
(`importlib.util.spec_from_file_location`) — not through Python's normal import system, not
through the FastMCP `server.py` files you'll find in each category folder. Those `server.py`
FastMCP servers exist and register tools with `@mcp_server.tool()`, but **they are only used when
`KALI_CONTAINER` env var is unset** (local dev without Docker) — see `mcp_client.py`'s
`_is_docker_available()`. In your actual docker-compose deployment, `command_builder.py` and
`mcp_client.py` import the tool's `build_command`/`parse` functions directly and shell out with
`docker exec` — the FastMCP JSON-RPC layer is bypassed entirely for the data plane. Don't spend
time debugging a `server.py` for a tool-execution bug in production mode; it isn't in the call
path.

**Layer 3 — special cases hardcoded in `command_builder.py`.** Not every tool goes through
Layer 2. `nmap_syn_scan`, `nmap_service_scan`, and `nmap_custom_scan` are built entirely inside
`_build_nmap_command()` in `command_builder.py` — there is **no** `mcp-servers/*/tools/nmap_*.py`
file at all (confirmed: only `mcp-servers/network/nmap_tools.py` and `nmap_wrapper.py` exist, and
neither is on this call path for these three tool names). This is where the container-safety logic
lives too: `-sS` (SYN scan, needs root) is silently rewritten to `-sT` (connect scan) unless
`privileged=true`, because the Kali container doesn't run as root by default. `domain_hunter` is
also special-cased (`_build_domain_hunter_command`) because it's a multi-file Python project run
in place with its own `main.py`, not a single-function adapter.

**Practical implication for you:** if you ask an AI to "add flag X support to nmap," it needs to
edit `_build_nmap_command()` in `command_builder.py`, *not* create or edit a file under
`mcp-servers/network/tools/`. If it does the latter, the change will silently do nothing, and
you'll re-ask "did it improve or not" without a way to tell — now you know exactly which file to
open and check.

For every other tool, adding one means: (a) add a `ToolDefinition` in `tool_registry.py`'s
category block, (b) add `mcp-servers/<category>/tools/<name>.py` with `build_command`/`parse`,
(c) optionally add it to `platform-mcp`'s typed tool list if you want it as a first-class MCP
function rather than reachable only via `platform_exec(tool_name=...)`.

---

## 4. Component reference

Grouped by plane. "Healthy signal" tells you what correct behavior looks like so you can tell a
regression from normal operation.

### Control plane — core pipeline

| File | Purpose | Healthy signal |
|---|---|---|
| `tool_execution.py` | The single execution pipeline (§2) | Every call ends with an audit log entry and either a `finding_titles` list or an explicit `next_hint` explaining why not |
| `tool_registry.py` | 879-line hand-authored catalog of every valid tool name/params/category | `get_tool_definition(name)` returns non-None for anything the LLM is told about |
| `command_builder.py` | Turns typed params + freeform flags into a CLI string | `build_command_for_tool()` never returns an empty string (raises `ValueError` instead) |
| `param_validator.py` | Shell-injection block + alias normalization + required-param check | Rejects only `;\|&`$()<>` and truly-missing targets — never rejects a "weird but valid" flag |
| `scan_budget.py` | Blocks expensive full-range scans without confirmation | Raises `ValueError` with a clear ask-the-human message, not a silent no-op |
| `exec_cache.py` | In-process TTL cache keyed on engagement+tool+params | Cache entries only for **successful, non-timeout, non-empty** stdout (see `set()`) |
| `mcp_client.py` | Spawns `docker exec` against the Kali container, parses response | `duration_seconds=0` on this path is expected, not a bug — see §2 step 8 |
| `governance.py` | Pre-execution scope check | Currently always `approved=True` — intentional, not broken |
| `session_context.py` | Resolves engagement_id/run_id from target/IDs | One engagement per distinct normalized target domain, reused via `get_latest_by_target` |

### Cognition plane — the "elite operator" logic

| File | Purpose | Healthy signal |
|---|---|---|
| `engagement_graph.py` | Postgres-backed node/edge graph (subdomains, hosts, IPs, ports, services) | Nodes/edges upsert idempotently — re-running the same tool doesn't duplicate the graph |
| `hypothesis_engine.py` | Universal "thinking cards" — vendor-agnostic SIGNAL→CONFIRM→GRADE prompts from regex signal classes in `config/thinking_model.yaml` | No per-vendor markdown files; cards say "use your knowledge," never a hardcoded conclusion |
| `finding_correlator.py` | Cross-finding hypothesis edges (same-IP+title, shared cookie domain, URL fanout) from `config/correlation_rules.yaml` | Every link/tag it creates is `evidence_grade=inferred`, never asserted as fact |
| `finalize_rules.py` + `finalize_readiness.py` | The "don't claim COMPLETE from chat memory" referee | Blocks CRITICAL/HIGH claims that rest only on hypothesis-only paths, per `config/finalize_rules.yaml` thresholds |
| `crown_jewels.py` | Scores assets by role-weight regex + tool-source count + graph-edge count | Score is a priority ordering hint, never gates execution |
| `coverage_engine.py` / `tool_coverage_store.py` | Tracks which tools ran against which assets | Used only to generate "you haven't tried X yet" cards — advisory |
| `escalation_registry.py` / `tech_dispatch.py` | Failure fallback chains / signal-based next-tool suggestions from YAML | Suggestions attach to `response.hybrid`, never auto-executed |
| `operator_memory.py` | Backing for `platform_think` / `platform_graph_link` / `platform_tag_asset` | Every hypothesis persists as an unverified finding — nothing is "just chat" |
| `ingest_promoter.py` | Universal regex ingest of stdout → structured findings, from `config/ingest_rules.yaml` | Runs for every tool call unconditionally, not per-tool special-casing |

### Operator front ends

| File | Purpose | Healthy signal |
|---|---|---|
| `agent_loop.py` | Built-in ReAct loop (recon+network only), used by the backend's own CLI/chat | Only shows tools where `installed=True`; blocks a tool+args pair after 2 identical failures (`_FAILURE_MEMORY`) |
| `llm_service.py` | LiteLLM wrapper — provider-agnostic model calls | Retries only on rate-limit/503/transient errors, with provider-aware backoff parsing (Groq/Gemini retry-after) |
| `platform-mcp/server.py` | ~35 `platform_*` cognition tools + typed action tools for OpenCode/Claude Desktop/ChatGPT | This is the richer, currently-primary way you actually drive engagements |
| `AGENTS.md` | The operator system prompt for the MCP path | Explicitly frames skills/config as *advisory*, never mandatory |

### Data model

| File | Purpose |
|---|---|
| `models/engagement.py`, `models/finding.py`, `models/run.py`, `models/tool_coverage.py` | SQLAlchemy ORM models — the actual Postgres schema |
| `findings_store.py` | Findings CRUD via `SessionLocal()` — genuinely Postgres-backed (confirmed: uses `db.merge()`/`db.commit()`) |
| `db/migrate.py` | Runs on every backend startup (see `main.py` lifespan) — auto-migrates schema |

---

## 5. The LLM/agent contract

This section answers "why did the LLM do that" questions.

**System prompt.** For the built-in loop, it's the literal `_SYSTEM_PROMPT` constant at the top of
`agent_loop.py` — read it directly when debugging odd behavior, it's short and explicit (e.g. "If a
tool fails 2+ times with the same tool+args, STOP," "Never invent targets," "Recon + network only
in this build"). For the MCP path, the equivalent is `AGENTS.md`, loaded by whichever MCP client
you're using (OpenCode/Claude Desktop) as its own system-prompt-equivalent — this is why behavior
differs between the two front ends even against the same backend.

**Tool schema exposure.** `agent_loop.py` filters the tool list to `installed=True` only
(`list_tools()` checks actual binary presence) — if a tool the LLM "should" know about never
appears in a tool call, check whether it's actually installed in the Kali container, not whether
the code registered it.

**Message history management** (`_prune_message_history`, `_trim_history` in `agent_loop.py`).
Keeps only the last ~12 messages plus the system + first user message, and — critically — strips
leading orphaned tool-call/tool-result messages from the truncated window. This exists because
Gemini specifically rejects a history where a tool-call/tool-result pair is split by truncation.
**If you switch models and see "invalid history" or similar 400s from the provider, this is the
first place to check** — the pruning logic was written against Gemini's constraints and may not be
sufficient for every provider's rules.

**Retry/backoff** (`llm_service.py::complete`). Only retries on rate-limit (429), transient
(503/"unavailable"/"high demand"), never on "too large"/"tokens per day" (fails fast — correctly,
since retrying won't fix a quota exhaustion). Backoff duration is parsed from the provider's own
error message when possible (Groq's "try again in Ns", Gemini's `retryDelay`), else exponential
`min(2**attempt, 15)`. **This means different providers fail differently under load** — Groq/Gemini
rate limits self-heal via retry; a model returning "too large" will not, and you'll see the error
surface immediately as `LLMServiceError`.

**Why behavior differs across models** (this directly answers your "if I don't use a good model, I
can't tell if it's the platform or the model" concern): the loop, prompt, tool schema, and pipeline
are **identical** regardless of model — `KNOWN_MODELS` in `llm_service.py` lists everything from
`groq/compound-mini` to `anthropic/claude-sonnet-4` to local `ollama/qwen2.5:14b`, all routed
through the same `acompletion()` call. Differences you see (tool-call malformed JSON, giving up
early, ignoring hints) are **model capability differences in instruction-following and function-
calling reliability**, not platform bugs — but the failure surfaces look identical (an odd tool
call, a premature "I'm done"). When an engagement goes badly, the first diagnostic question should
be "what model was configured" (`GET /api/v1/models` or check `.env`'s `LLM_MODEL`), before
assuming a code regression.

**Turn limits.** `LLM_MAX_AGENT_TURNS` (default 40, see `docker-compose.yml`) caps the ReAct loop.
Hitting it returns `error="max_turns_exceeded"` with everything done so far — this is not a crash,
it's an intentional stop; "send another message to continue" is literally in the response text.

---

## 6. Config-driven behavior map

`config/README.md` (already in your repo) states the precedence rule accurately, and I confirmed
it in code (`hypothesis_engine.py`, `finding_correlator.py`, `ingest_promoter.py`,
`finalize_rules.py` all try `.yaml` first, `.json` only as a fallback if yaml is absent):

> **YAML is the source of truth.** JSON mirrors next to several YAML files are legacy holdovers —
> editing the `.json` version of a file that has a `.yaml` sibling **does nothing** unless the
> yaml is deleted or missing. This is the single most likely "I changed the config and nothing
> happened" trap in the repo.

| File | Governs | Loaded by |
|---|---|---|
| `ingest_rules.yaml` | stdout → findings regex rules (subdomain, port, tech fingerprint, SPA demotion, etc.) | `ingest_promoter.py` |
| `correlation_rules.yaml` | Cross-finding hypothesis edges/tags | `finding_correlator.py` |
| `thinking_model.yaml` | Universal signal-class think/confirm/grade cards + crown-jewel role weights | `hypothesis_engine.py` |
| `escalation_matrix.yaml` | Tool-failure fallback chains (beyond the hardcoded `_STATIC_FALLBACKS`) | `escalation_registry.py` |
| `tech_dispatch.yaml` | Signal → suggested-next-tool dispatch | `tech_dispatch.py` |
| `finalize_rules.yaml` | Evidence thresholds for blocking COMPLETE/CRITICAL claims | `finalize_rules.py` |
| `parallelism.yaml` | Job concurrency caps + "this tool is slow, consider a background job" hints | `parallelism_config.py` |
| `playbooks.yaml` | Advisory named workflows (`platform_playbook`) | `platform-mcp/server.py` |
| `recon_network_tools.yaml` | Tool catalog context for `/hybrid/*` endpoints | `hybrid.py` endpoints |
| `kali_allowlist.json` | Allowlisted commands for `platform_shell` | `shell_exec.py` |

All configs are loaded through `@lru_cache(maxsize=1)` — **they are cached in the Python process
after first read**. If you edit a YAML file and don't see the change take effect, you likely need a
backend restart, or the specific `reload_*()` function that some modules expose (e.g.
`reload_ingest_rules()`, `reload_finalize_rules()`, `reload_correlation_rules()`) needs to be
called — check whether the endpoint you're using actually calls it.

---

## 7. Debugging playbook

Symptom → most likely file(s) to check, in order.

**"The LLM called a tool that doesn't exist / got a 404 Tool not registered."**
→ `tool_registry.py` — is there a `ToolDefinition` entry? Check the fuzzy-match hint in the error
first (`suggest_tool_names`), it's usually right about what was meant.

**"The tool ran but returned the exact same output as last time, even though I changed something."**
→ `exec_cache.py` — 1-hour TTL, keyed on exact params. Look for `cache_hit: true` in the response.
Force with `force_refresh=true`.

**"I edited the tool's Python file and nothing changed."**
→ Is it `nmap_syn_scan`/`nmap_service_scan`/`nmap_custom_scan`? Those live in
`command_builder.py::_build_nmap_command`, not in `mcp-servers/`. For everything else, confirm the
file path matches exactly `mcp-servers/<category>/tools/<tool_name>.py` — `_load_build_command`
does a raw path check and silently returns `None` (→ later raises `ValueError`) on any mismatch.

**"A scan I expected to run just got rejected with a 400."**
→ Read `detail` in the error body. It's one of: `param_validator.py` (missing/empty primary
target, or a blocked shell metacharacter), or `scan_budget.py` (full/wide port range without
`confirm_expensive=true`). Both raise human-readable `ValueError` text — read it, it tells you
exactly which gate fired.

**"Everything eventually hangs / stops accepting new tool calls after a while."**
→ `command_builder.py`'s `_kill_and_reap()` docstring documents this exact failure mode: a timed-
out `docker exec` subprocess that isn't killed and reaped leaks a process slot. Check whether every
`asyncio.TimeoutError` branch in `mcp_client.py` actually calls `_kill_and_reap(proc)` — if a new
code path was added (by you or an AI) that spawns a subprocess without this, this symptom will
return.

**"Tool calls to the Kali container silently fail or behave like nothing is installed."**
→ Check whether `docker` CLI is available *inside the backend container* (`_is_docker_available()`
checks `shutil.which("docker")`). If it's missing, `KALI_CONTAINER` being set doesn't help —
`call_tool()` falls through to the local-stdio-server path, which tries to run
`mcp-servers/<category>/server.py` as a **local subprocess inside the backend container**, where
the actual pentest binaries aren't installed. This looks like "the tool is broken" but is actually
a docker-socket/CLI availability issue.

**"The findings/graph don't show something I saw in the raw output."**
→ This is by design, not a bug — see `ingest_promoter.py`'s regex rules in
`config/ingest_rules.yaml`. Only patterns with a rule get promoted to a structured `Finding`.
Everything else is still captured as a raw "observation" finding and in the full stdout artifact
(`platform_artifact` / `stdout_index.py`) — nothing is silently discarded, but not everything is
*structured*. If you want more things structured, this is where you add a rule (and the YAML file,
not the JSON mirror).

**"The agent stopped early / declared victory without deep evidence."**
→ Two independent systems fight this: `finalize_rules.py` (blocks weak COMPLETE/CRITICAL claims —
check `config/finalize_rules.yaml` thresholds) and the `AGENTS.md`/`_SYSTEM_PROMPT` instructions
telling the model not to. If it still happens, it's very likely a **model capability gap** (weaker
models ignore soft instructions more), not a missing platform mechanism — check §5's model-
capability note before assuming a code fix is needed.

**"The agent kept retrying the same failing tool call over and over."**
→ `agent_loop.py`'s `_FAILURE_MEMORY` should block an identical `tool_name(args)` signature after 2
failures. If you're on the MCP-driven path (OpenCode etc.) instead of the built-in loop, **this
protection does not exist there** — `platform-mcp/server.py` has no equivalent failure-memory
mechanism; the MCP client itself (OpenCode) is responsible for not looping, per its own reasoning.
This is a real difference between the two front ends worth knowing.

**"I changed a YAML config and nothing happened."**
→ `@lru_cache` on every config loader (§6). Restart the backend, or find and call the module's
`reload_*()` function if one is wired to an endpoint.

**"Different runs against the same domain created two different engagements."**
→ `session_context.py::normalize_target()` — check whether the target string differs in a way
that survives normalization (e.g. trailing slash, `www.` prefix, scheme). `get_latest_by_target`
does an exact match on the normalized string.

---

## 8. Latency map — where time actually goes

- **LLM round trips** dominate wall-clock time for any multi-tool engagement — each turn is a full
  `acompletion()` call (`llm_service.py`), and `LLM_REQUEST_TIMEOUT` (default 300s) plus retry
  backoff (§5) can each add tens of seconds under provider rate limiting.
- **Tool subprocess time** is bounded by the per-call `timeout` parameter
  (`LLM_TOOL_TIMEOUT`, default 900s in compose) but **is not actually measured/recorded**
  (`duration_seconds=0` on the docker-exec path — see §2 step 8). If you want real per-tool timing
  data, you'd need to add a wall-clock measurement around the `asyncio.wait_for(proc.communicate())`
  call in `mcp_client.py::_call_via_docker_exec` — it isn't there today.
- **The exec cache** (`exec_cache.py`) is the only thing that makes a repeated identical call fast
  (near-instant) — everything else re-runs the full pipeline including the real subprocess.
- **Sequential vs parallel**: the base agent loop runs one tool call at a time per turn (though it
  can issue multiple `tool_calls` in one LLM turn — check whether your loop processes them
  sequentially in the `for tc in tool_calls` block in `agent_loop.py`, which it does). Real
  parallelism only happens via `platform_job_start` (background jobs, `job_store.py`) or
  `platform_fanout_assets` (one tool across many assets, `fanout.py`) — both are opt-in, the LLM
  has to choose to use them; nothing auto-parallelizes a slow scan.
- **`parallelism.yaml`** (via `parallelism_config.py`) only emits *soft hints* ("this tool is slow,
  consider a background job") attached to `response.hybrid.parallel_note` — it never forces
  backgrounding.
- **Docker exec overhead itself**: every tool call pays the cost of spawning a new `docker exec`
  process from the backend container against the sibling Kali container over the mounted host
  docker socket — this is not pooled or reused, each call is a fresh process spawn.

---

## 9. Persistence map

What survives a `docker compose restart backend` / `down` and what doesn't — this matters because
"did AI's change actually take effect or did I just get lucky before a restart wiped it" is exactly
your stated verification problem.

**Durable (Postgres, via SQLAlchemy models + Alembic migrations run automatically on startup —
`main.py` lifespan → `db/migrate.py::run_migrations()`):**
- Engagements (`models/engagement.py`)
- Runs (`models/run.py`)
- Findings (`models/finding.py`) — confirmed: `findings_store.py` uses `SessionLocal()`,
  `db.merge()`, `db.commit()`
- Tool coverage (`models/tool_coverage.py`)
- Engagement graph nodes/edges (`engagement_graph.py` — same DB session pattern)

**In-process only (Python dict/list in memory — gone on restart, not shared across multiple
backend replicas if you ever scale beyond one):**
- `exec_cache.py` — the 1-hour TTL cache
- `audit_log.py` — confirmed: `threading.Lock()` + no DB import; every audit entry from §2 step 14
  is lost on restart
- `job_store.py` — background job records
- LLM service singleton / config hash caching in `llm_service.py`

**Practical rule of thumb:** if you're trying to verify "did this fix persist correctly," check
Postgres directly (`docker compose exec postgres psql -U pentest -d pentest`) for findings/graph
data — don't trust the audit log or job list to still be there after any restart.

---

## 10. How to verify an AI-made change yourself

Concrete, in this repo, right now:

1. **Run the existing test suite first, before and after the change.** You already have real
   coverage: `backend/tests/` has 22 test files including phase-specific smoke tests
   (`test_operator_memory_phase1.py`, `test_open_loops_phase2.py`, `test_ingest_phase3.py`,
   `test_parallelism_phase4.py`, `test_finalize_phase5.py`, `test_network_surface_m5.py`,
   `test_fanout_m6.py`, `test_operator_recall_phase7.py`), plus general ones
   (`test_command_builder.py`, `test_tools.py`, `test_engagements.py`, `test_session_context.py`).
   Run `cd backend && python -m pytest tests/ -v` and diff pass/fail counts. This alone answers
   "did it break something" for the parts that have tests — which is most of the phased cognition
   work.
2. **Check which of the four gates in §2 (steps 3–6) the change touches**, and manually construct
   a call that would exercise it — e.g. if the AI touched `param_validator.py`, try a call with a
   deliberately missing target param and confirm you still get the expected 400, not a silent pass-
   through.
3. **If it touched a tool adapter, confirm which layer it actually edited** (§3) — for nmap tools
   specifically, verify the AI edited `command_builder.py`, not a nonexistent
   `mcp-servers/network/tools/nmap_*.py`.
4. **If it touched a YAML config, remember the cache** (§6) — restart the backend before deciding
   the change "didn't work."
5. **Check Postgres directly** for anything claimed to be persisted (§9) rather than trusting the
   chat transcript or the audit log.
6. **Read the diff for new `except Exception: pass`-style swallowing.** This codebase already has
   several deliberate broad excepts (e.g. `tool_execution.py`'s findings-ingest try/except, or the
   parse-failure swallow in `mcp_client.py`) — they're intentional ("never let a
   parsing/ingest failure break the tool call"). A *new* one added to fix a symptom is a red flag:
   it usually means the AI made an error disappear from the log rather than fixing its cause.

---

## 11. Extension points

**Adding a new tool in an existing category** (e.g. another web tool): add
`mcp-servers/web/tools/<name>.py` with `build_command`/`parse`, add a `ToolDefinition` to the
`WEB_TOOLS` block in `tool_registry.py`, done — it's reachable via `platform_exec` immediately.
Add it to `platform-mcp/server.py`'s typed tool list only if you want it as a named first-class MCP
function rather than routed through the generic executor.

**Adding a whole new pentest phase** (e.g. "web" or "exploit" becoming first-class like
recon/network are today): the tool adapters for web/exploit/creds/vuln/cloud/forensics/binary
**already exist** (§ from the prior codebase analysis: 26 web tools, 4 exploit, 4 creds, 2 vuln,
13 cloud, 7 forensics, 16 binary — all with the Layer-2 adapter contract already in place). What's
missing to make a phase "first-class" the way recon/network are:
- A phase-specific system prompt section (like `_SYSTEM_PROMPT`'s "BOUNDARIES: Recon + network
  only in this build" — that line is the literal gate keeping the built-in loop scoped; removing/
  extending it is a one-line change, but should be deliberate since the whole prompt was tuned
  around recon/network behavior).
- Phase-specific skills under `skills/<phase>/` (recon and network already have
  `phase-overview.md`, `agent-system.md`; exploit/web have thinner skill folders today).
- Optionally, phase-aware config entries in `thinking_model.yaml`/`escalation_matrix.yaml` if you
  want universal-thinking-card coverage for that phase's signal types.
- The cognition plane (graph, correlator, finalize rules, ingest) is **already phase-agnostic** —
  it operates on findings/stdout regardless of which category produced them, so it needs no changes
  to support a new phase.

**Changing the LLM provider/model**: `.env`'s `LLM_MODEL` + matching API key — no code change
needed for anything in `KNOWN_MODELS` (`llm_service.py`). For a provider not in that list, LiteLLM
likely still supports it; add the provider→env-var mapping to `_PROVIDER_ENV_VAR`.

---

## 12. File index

One line each, for `backend/src/pentest_platform/services/` — scan this when you're not sure which
file owns a behavior.

```
adaptive_depth.py       — depth/coverage heuristics for how deep to probe a target
agent_arg_normalizer.py — maps domain/host/url/target aliases to a tool's real param name
agent_assist.py         — enriches tool results shown back to the agent (signatures, hints)
agent_common.py         — shared helpers across agent front ends
agent_loop.py           — built-in ReAct loop (recon+network), §5
artifacts.py            — writes full stdout to disk, returns a path
attack_surface_tree.py  — hierarchical seed→subs→hosts→ips→ports→services view
audit_log.py            — in-memory audit trail, §9
command_builder.py      — CLI string assembly, §3
commander_agent.py      — orchestrates multi-phase/commander-level flow
commander_context.py    — packages context for a "commander" LLM role
context_delta.py        — computes what's new since last context fetch
coverage_engine.py      — coverage-gap detection (advisory)
crown_jewels.py         — asset importance scoring
engagement_graph.py     — Postgres-backed graph, §4/§9
engagement_store.py     — engagement CRUD
escalation_registry.py  — failure→fallback-tool suggestions
evidence.py             — evidence formatting helpers
evidence_chain.py       — derived_from parent/child evidence walk
exec_cache.py           — TTL result cache, §2/§9
fanout.py               — one tool across many assets, §8
finalize_readiness.py   — "are we ready to call this COMPLETE" check
finalize_rules.py       — evidence-threshold config loader, §4
finding_correlator.py   — cross-finding hypothesis edges, §4
findings_store.py       — Postgres-backed findings CRUD, §9
governance.py           — permissive no-op scope check, §2/§4
graph_query.py           — read-side graph query API
hypothesis_engine.py    — universal thinking cards, §4
ingest_promoter.py      — regex stdout→finding rules, §2/§6
job_store.py            — background job tracking, §8
knowledge_browser.py    — browsing stored knowledge/memory
llm_service.py          — LiteLLM wrapper, §5
mcp_client.py            — docker exec dispatch, §2/§3
network_surface.py      — network-layer surface aggregation
open_loops.py           — "what's unexplored" suggestions
operator_memory.py      — backing for platform_think/graph_link/tag_asset
operator_recall.py      — memory search backing
orchestrator.py          — higher-level run orchestration
package_install.py       — on-demand tool install helper
param_validator.py       — injection block + required-param gate, §2/§4
parallelism_config.py    — job caps + soft parallel hints, §8
phase_agent.py           — per-phase agent variant
phase_reflection.py      — Shannon-style coverage reflection
phases.py                — phase enum/definitions
recovery_bridge.py       — HexStrike-derived error-recovery bridge
report_outline.py        — report skeleton generation
run_store.py             — run CRUD, tied to engagements
scan_budget.py            — expensive-scan gate, §2/§4
script_exec.py            — platform_script custom code execution
session_context.py       — engagement/run resolution, §2/§4
shell_exec.py             — platform_shell allowlisted execution
skills_loader.py          — loads skills/*.md files
stdout_index.py           — stdout artifact index, §2
summary_agent.py          — turns tool response into findings
target_analysis.py        — target shape/type analysis (domain vs IP etc.)
target_utils.py           — target extraction/normalization helpers
task_registry.py          — tool "capability" metadata (freeform field, phase, primary param)
tech_dispatch.py          — signal→next-tool dispatch, config-driven
tool_coverage_store.py    — which tools ran against which assets
tool_discovery.py         — builds LLM-facing tool schemas
tool_execution.py         — THE pipeline, §2
tool_failure_hints.py     — human-readable failure explanations
tool_registry.py          — the 879-line tool catalog, §3/§4
tool_runner.py            — lower-level run helper
workflow_runner.py        — multi-step named workflow execution
```

---

*This document reflects the codebase as read on 2026-07-24. It will drift the moment you (or an
AI) change the files it describes — treat it as a map of the terrain at this point in time, not a
living spec. When in doubt, the code is the source of truth; this document just tells you where to
look.*
