# Plan 03 — Crown Jewels Removal

**Baseline:** `d7a4594` · **Risk:** Medium (35 files, incl. 2 MCP tools + API + skills) · **Depends on:** nothing.

## Why

Crown-jewel scoring is a pre-computed asset ranking (`rank_crown_jewels` weights login/admin/API/DB roles). Decision: remove it — the driver prioritises from ports/services/findings itself, and the ranking has no consumer that *gates* anything (verified: it is informational only). Its one behavioural bug (silently dropping assets scoring ≤0 instead of showing them) is moot once the whole thing goes.

## Blast radius (35 files matched `crown_jewel|rank_crown_jewels|tag_asset|crown`)

Core: `backend/src/osprey/services/crown_jewels.py` (delete whole file). MCP: `platform-mcp/server.py` (`platform_crown_jewels`, `platform_tag_asset` registrations). Consumers: `commander_context.py`, `report_outline.py`, `graph_query.py`, `finding_correlator.py`, `operator_memory.py`, `fanout_assets.py`, `parsers/creds.py`, `api/v1/endpoints/hybrid.py`, `api/v1/endpoints/engagements.py`, `schemas/hybrid.py`, `config/thinking_model.yaml`, `config/playbooks.yaml`, `config/correlation_rules.yaml`. Docs/skills: `AGENTS.md`, many `docs/*.md`, many `skills/*.md`.

**Note the two concepts are separable:** `platform_tag_asset` writes an asset tag; `rank_crown_jewels` reads tags + roles to rank. Confirm during the work whether asset *tagging* has any other legitimate use (e.g. operator notes) before deleting `platform_tag_asset` — opencode flagged this open question. If tagging is only ever consumed by crown-jewel ranking (grep the tag read path), remove both. If tagging has independent value, keep `platform_tag_asset` and remove only the ranking. **Resolve this by grep before Step 3, do not guess.**

## Steps

### Step 1 — Confirm no gate depends on it
`grep -rn "crown_jewel" backend/src/osprey/services` and read each hit: confirm every consumer *reads* the ranking for display/context only and none uses it to skip/block/filter work. If any consumer gates on it, that gate must be removed too (advisory principle) — report it. Expected: all informational.

### Step 2 — Delete the core
- Delete `backend/src/osprey/services/crown_jewels.py`.
- Remove its `config/thinking_model.yaml` weights block (that file is `crown_jewels.py`'s config, per earlier audit `crown_jewels.py:29`) — delete the now-orphaned keys.

### Step 3 — Remove the MCP tools
In `platform-mcp/server.py`: remove the `@mcp.tool()` registration and function body for `platform_crown_jewels`, and (pending the Step-0 tagging decision) `platform_tag_asset`. Remove their entries from any tool-list/catalog doc.

### Step 4 — Reconnect consumers
- **`commander_context.py`**: it injects crown-jewel ranking into the Commander's context. Remove that section cleanly; the phase/findings context remains. Verify the assembled context is still valid (no dangling "Crown jewels:" header with empty body).
- **`report_outline.py`** / report pipeline: remove the crown-jewel section from the outline; ensure the outline still renders without it.
- **`graph_query.py`**, **`finding_correlator.py`**, **`operator_memory.py`**, **`fanout_assets.py`**, **`parsers/creds.py`**: remove crown-jewel reads/writes; ensure each function's remaining logic is whole.
- **API**: `api/v1/endpoints/hybrid.py`, `engagements.py`, `schemas/hybrid.py` — remove crown-jewel fields from request/response schemas; confirm no client (CLI `cli/api/*.py`, dashboard) still requests them. Grep the CLI for the endpoint/field; if the CLI reads it, update the CLI too.
- **`config/playbooks.yaml`**, **`config/correlation_rules.yaml`**: remove crown-jewel references.

### Step 5 — Docs & skills
Rewrite (don't just delete sentences from) `AGENTS.md` and every `skills/*.md` / `docs/*.md` that instructs the operator to "deepen crown jewels first" etc. — replace with the grade-free prioritisation guidance ("prioritise from open ports, service roles, and confirmed findings"). This keeps the methodology coherent instead of leaving a hole where a step used to be.

## Reconnect summary
The one real capability lost is "here are the N highest-value hosts." Its replacement is the driver's own judgement over data it already sees (ports/services/findings) — so the skills text in Step 5 is the reconnection: it tells the driver to do the prioritisation the ranking used to hand it.

## Done criteria
- `grep -rn "crown_jewel\|rank_crown_jewels" backend platform-mcp config` returns nothing.
- `grep -rn "platform_crown_jewels" .` returns nothing (docs included).
- `cd backend && python -m pytest tests/ -q` passes (remove/adjust any crown-jewel test).
- CLI `/status`, `platform_context`, and a report render end-to-end with no crown-jewel section and no error.
- If `platform_tag_asset` was kept: it still works and its output is consumed by something real; if removed: no reference remains.
