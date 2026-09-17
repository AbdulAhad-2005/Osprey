# Plan 06 — Fan-out Consolidation (two batch engines → one)

**Baseline:** `d7a4594` · **Risk:** Medium · **Depends on:** nothing (but coordinate with Plan 03 — `fanout_assets.py` has crown-jewel references to remove there).

## Why

Two independently-built "run one tool across many targets, with dry-run/confirm safety" mechanisms exist, overlapping heavily and diverging in behaviour:
- `backend/src/osprey/services/fanout.py` (sister-domain enum): **sequential** `for` loop over `execute_tool_request`, own 4-tool allowlist (`_ALLOWED_ENUM_TOOLS`, ~29-36), own dry-run/confirm gating, own `_MAX_SISTER_GAPS=24` cap.
- `backend/src/osprey/services/fanout_assets.py` (general asset batch): **concurrent** `asyncio.Semaphore` + `gather` (~146-163), own 15-tool allowlist (`_ALLOWED`, ~19-37), own dry-run/confirm gating, own `max_assets<=100` cap.

`fanout.py`'s sequential loop is strictly worse for large lists — the concurrency fix that made `fanout_assets.py` fast was never back-ported. And both hardcode an arbitrary tool allowlist that rejects any tool not on the list, forcing a driver that wants to batch e.g. `nuclei_scan` across 40 hosts into a `platform_script` workaround for something that should be one call.

## Design decision

One fan-out primitive: concurrent (semaphore-bounded `gather`, from `fanout_assets.py`), one dry-run/confirm implementation, and **no hardcoded tool allowlist** — any catalog tool may be fanned out (the shared kernel already applies RoE/validation/rate-governing per call via `tool_execution.execute_tool_request`, so an allowlist here is redundant gatekeeping). Sister-domain enum becomes a *caller* of the one primitive with a specific tool list passed in, not a second engine.

## Steps

### Step 1 — Choose the survivor and its shape
Keep `fanout_assets.py`'s concurrency model as the base. Define one entry point, e.g. `fanout(tool_name, assets, params, *, max_concurrency, dry_run, confirm) -> results`. Remove the `_ALLOWED`/`_ALLOWED_ENUM_TOOLS` allowlists — rely on the shared kernel's per-call RoE/validation (verify `execute_tool_request` enforces those regardless of caller; earlier audit confirmed it does). Keep the `max_assets`/concurrency caps as *resource-safety* caps, but make them overridable params with sane defaults (per Plan 05 principle), not hard `le=100` Pydantic walls.

### Step 2 — Re-express sister-domain enum as a caller
Whatever `fanout.py` did for sister domains becomes a thin function that calls the unified `fanout()` with the sister-enum tool list and the `_MAX_SISTER_GAPS` cap passed as the `max_assets`/limit argument. Delete `fanout.py`'s own loop, allowlist, and dry-run/confirm code.

### Step 3 — Delete and reconnect
- Delete `fanout.py` (or reduce it to the thin sister-enum caller from Step 2 if a named entry point is depended upon — grep callers first).
- Update every caller of the old `fanout.py` / `fanout_assets.py` entry points: `platform_fanout` and `platform_fanout_assets` MCP tools in `platform-mcp/server.py`, plus any backend caller. If the two MCP tools now do the same thing, consider collapsing to one (`platform_fanout`) and removing the redundant registration — but only if no external harness contract depends on both names; if unsure, keep both names as thin wrappers over the one implementation and note it.
- Remove crown-jewel references in `fanout_assets.py` (coordinate with Plan 03).

## Reconnect summary
All batch execution flows through one concurrent primitive with one safety model. The MCP surface keeps working (same tool names, or a documented collapse); sister-enum keeps working as a caller.

## Done criteria
- Only one fan-out implementation remains (one semaphore/gather loop, one dry-run/confirm block, one allowlist-free path).
- A driver can fan-out any catalog tool (e.g. `nuclei_scan`) across N assets without hitting a tool-allowlist rejection.
- Sister-domain enum still works (test or manual trace).
- `grep -rn "_ALLOWED_ENUM_TOOLS\|_ALLOWED =" backend/src/osprey/services/fanout*.py` returns nothing.
- `cd backend && python -m pytest tests/ -q` passes.
