# Plan 01 — Truncation Unification (the "raw output reaches the driver" fix)

**Baseline:** `d7a4594` · **Risk:** Medium · **Depends on:** nothing · **Do first.**

## Why

An external comparison found the platform surfaced one DB table where a competitor dumped 22. Root cause is not a chaining engine — it is that a tool's raw stdout is truncated to a small preview before the driver (LLM / external harness) ever sees it, so the driver can't act on data it never received. There are **five independent truncation constants** invented separately across five files — a scatter problem in its own right. The output is not destroyed (full stdout is saved to a Kali-side artifact via `platform_artifact`), but nothing makes retrieving it urgent, so the driver reasons over a stub.

### The five caps (verified at `d7a4594`)

| # | Location | Constant / logic | Path it governs |
|---|---|---|---|
| 1 | `backend/src/osprey/services/mcp_client.py:64` | `_STDOUT_MAX = 50_000` | subprocess capture (outermost; before parse/ingest) |
| 2 | `backend/src/osprey/services/summary_agent.py:37` | `_MAX_STDOUT_FOR_LLM = 12000` | input to the LLM compressor (backend self-driving agent only) |
| 3 | `platform-mcp/server.py:1076-1078` | `stdout_cap = 2500 if digest else 12000` (+ `head_cap`/`tail_cap`) | **every external MCP client + the CLI** (this is the one the tester hit) |
| 4 | `backend/src/osprey/services/agent_common.py:48` | `TOOL_RESULT_MAX = 2500`, applied at `phase_agent.py:493` | backend self-driving agent |
| 5 | `cli/agent/loop.py:292` | `result_cap = 3000 if tool_schema_budget_tokens>0 else 12000` | CLI agent loop (applied *on top of* #3) |

The CLI path is capped twice (#3 then #5). The digest gate at #3 means "almost any multi-line output" gets the 2500 cap, because `digest_tool_output` (`backend/src/osprey/services/parsers/registry.py:248-259`) returns a non-empty digest for nearly any output >3 lines.

## Design decision

Introduce **one** truncation policy, owned in a single module, that all paths call. It must be **tool-aware**: high-value exploitation output (sqlmap dumps, ffuf/feroxbuster match lists, hydra results, gobuster) gets a large budget; routine inventory output (subfinder/httpx lists) keeps a modest budget. The digest existing is *not* a reason to shrink the raw preview — the driver may need the raw rows the digest summarised away.

This is deliberately **not** "delete all caps": unbounded stdout genuinely filled external-harness context on long sessions (see the honest comment at `server.py:1072`). The fix is one honest, generous, tool-aware policy — not five conflicting magic numbers, and not zero.

## Steps

### Step 1 — Create the single policy module
Create `backend/src/osprey/services/output_budget.py` exposing:
```python
def stdout_budget(tool_name: str) -> int:
    """Chars of raw stdout to surface to a driver for this tool."""
```
- A default (suggest 20_000).
- A high-value set (suggest 200_000) for tools whose *value is in the volume of rows*: `sqlmap_scan`, `ffuf_scan`, `feroxbuster_scan`, `gobuster_scan`, `hydra_attack`, `katana_crawl`, `hakrawler_crawl`, `gau_discovery`, `waybackurls_discovery`, `nuclei_scan`, `arjun_scan`, `x8_parameter_discovery`, plus `platform_shell`/`platform_script` (arbitrary user output). Confirm the exact catalog names against `tool_registry.py` before hardcoding.
- Read the numbers from `config/parameter_profiles.yaml` (or a new small `config/output_budget.yaml`) so they are tunable without a code change — but the module owns the defaults so a missing config never means "0".
- When truncating, always keep head + tail and insert the existing `platform_artifact` pointer marker (reuse the marker text already in `server.py:1085-1088`) so the driver knows the full dump is one call away.

### Step 2 — Route the MCP/CLI formatter through it (cap #3)
In `platform-mcp/server.py:_format_exec_result` (line 1057): delete the `digest`-gated `stdout_cap/head_cap/tail_cap` block (1075-1089) and replace with a call to the shared policy keyed on `data.get("tool_name")`. The digest still renders as `PARSED SUMMARY` (line 1103-1104) — it is additive, not a reason to shrink raw.
- `platform-mcp/` is a separate process from `backend/`; it cannot import `backend.src...`. Either (a) duplicate the tiny budget table into a `platform-mcp` helper that reads the same `config/*.yaml`, or (b) have the backend include the already-budgeted stdout in the `/api/v1/mcp/execute` response so the MCP server does no capping of its own. **(b) is preferred** — it keeps the policy truly single-sourced in the backend and makes the MCP server a dumb formatter. Choose (b) unless the response-size cost is shown to be a problem.

### Step 3 — Route the backend agent path through it (caps #2 and #4)
- `agent_common.py:48`: delete `TOOL_RESULT_MAX = 2500`. `phase_agent.py:493` (`format_tool_result(..., max_length=TOOL_RESULT_MAX)`) must instead use the per-tool budget. Trace `format_tool_result` (in `tool_discovery.py` per earlier audit) and make its `max_length` come from `stdout_budget(tool_name)`.
- `summary_agent.py:37` `_MAX_STDOUT_FOR_LLM = 12000`: this feeds the LLM *compressor*. Raising it costs compressor tokens. Keep a compressor input cap but source it from the same module (a separate `compressor_input_budget()` is acceptable — the compressor's job is genuinely different from "what the driver sees"). Document why it stays separate so a future reader doesn't "unify" it wrongly.

### Step 4 — Route the CLI second cap through it (cap #5)
`cli/agent/loop.py:292`: the CLI applies its own `result_cap` on top of the already-budgeted server output — double truncation. Remove the CLI's independent cap for the non-budget case; keep only the *schema-budget-mode* trim (when `tool_schema_budget_tokens>0` the operator explicitly asked for a lean context) and even then source the number from the shared policy, not a local `3000`.

### Step 5 — Leave cap #1 alone, but document it
`mcp_client.py:64` `_STDOUT_MAX = 50_000` is the subprocess-capture ceiling *before* parsing/artifact-writing. If any high-value tool's budget in Step 1 exceeds 50_000, this cap would silently win. Either raise `_STDOUT_MAX` above the largest per-tool budget, or (better) ensure the full stdout is written to the artifact file *before* this cap is applied so the artifact is always complete even when the in-memory copy is clipped. Verify the artifact write in `tool_execution.py:551-589` happens on full stdout, not the clipped copy — if it's already on full stdout, this cap only limits the in-memory path and is fine to raise modestly.

## Reconnect
- Anything importing `TOOL_RESULT_MAX` from `agent_common.py` (grep it) must switch to the new module.
- The `platform_artifact` pointer marker must remain wherever truncation happens, so "there's more, fetch it" is always signalled.

## Files in scope
`backend/src/osprey/services/output_budget.py` (new), `platform-mcp/server.py`, `backend/src/osprey/services/agent_common.py`, `phase_agent.py`, `summary_agent.py`, `tool_discovery.py`, `cli/agent/loop.py`, `mcp_client.py`, `config/parameter_profiles.yaml` or new `config/output_budget.yaml`.

## Out of scope
Parser logic (what becomes a structured Finding) — that is plan 02. This plan only governs how much *raw stdout* the driver sees.

## Done criteria
- `grep -rn "2500\|TOOL_RESULT_MAX\|_MAX_STDOUT_FOR_LLM\|3000" backend cli platform-mcp` shows no independent stdout-truncation magic numbers outside `output_budget.py`/config.
- A `sqlmap_scan` run that dumps 20+ tables returns all table names in the driver-visible result (test with a fixture or a controlled target), not a head+tail stub.
- Existing tests pass: `cd backend && python -m pytest tests/ -q`.
- New test: given a fake 100 KB sqlmap stdout, the MCP-formatted result contains the last table name (tail preserved) AND far more than 2500 chars.
