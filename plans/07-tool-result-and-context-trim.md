# Plan 07 — Tool-Result & Context Trim (backend agent path)

**Baseline:** `d7a4594` · **Risk:** Medium · **Depends on:** Plan 01 (truncation), Plan 02 (report/finding shape).

## Why & scope correction

Opencode's "7 layers of noise on every tool result" is only true on the **backend self-driving agent path** (`backend/src/osprey/platform/adaptation.py:enrich_tool_result`), NOT on the MCP/CLI path. The MCP/CLI formatter (`platform-mcp/server.py:_format_exec_result`, verified) is already lean: header, success line, command, tool, digest, cache note, stdout, stderr, error, top-15 findings, artifact pointer. So this plan is scoped to the backend agent path plus a light audit of the MCP formatter — it must not "fix" noise that isn't there.

`enrich_tool_result` (`adaptation.py:75-170`) appends, in order: raw stdout → PARSED SUMMARY (digest, success only) → repeat-failure warning (failure only) → failure analysis (failure only) → failure hints (failure only) → orchestration/escalation hints (**already gated to `if not useful_output`**, i.e. failure/empty only — verified at `adaptation.py:135`) → SESSION FINDINGS snapshot (always) → situational brief (always).

## Decision

Per the maintainer's list: remove **situational brief** and **escalation hints** from tool results; keep raw output + parsed summary + findings list. Situational/phase context belongs in `platform_context`, fetched deliberately, not stapled to every tool return.

Nuance to respect (don't blindly delete): the escalation hints are *already* failure-only and are advisory text, so they cost nothing on a successful run. They are still being removed per decision — but verify that the *factual* `next_hint` marker (the kernel recording "auto-fallback ran / wide scan auto-chunked", surfaced at `server.py:1130`) is a **different** thing and is KEPT. That marker is a fact about what the kernel did, not a nudge. Do not remove factual markers; remove advisory "you should try X next" nudges.

## Steps

### Step 1 — Trim `enrich_tool_result` (`adaptation.py`)
- Remove the `build_situational_brief` call and its `parts.append` (159-168).
- Remove the orchestration/escalation-hints block (135-150) **only for its advisory-nudge content**. If `build_orchestration_meta` also computes the factual `next_hint` marker, preserve that path (route the factual marker to the response's `next_hint` field the MCP formatter already renders) and delete only the advisory text formatting.
- Keep: raw `base_text` (80), PARSED SUMMARY (92-95), failure analysis + repeat warning (they are genuinely useful *on failure* and are failure-gated — the maintainer's list did not ask to remove failure diagnostics; keep them), SESSION FINDINGS snapshot (152-157).
- Result parts on a successful run: raw stdout → PARSED SUMMARY → SESSION FINDINGS. Three layers, matching the target.

### Step 2 — Delete now-orphaned code
- `build_situational_brief` (`backend/src/osprey/platform/situational_context.py`) — if `enrich_tool_result` was its only caller, delete the function and file. Grep first: `grep -rn "build_situational_brief\|situational_context" backend platform-mcp`. If `platform_context` also builds situational info via a *different* function, good — the deleted one was the tool-result duplicate. If `platform_context` was *also* calling this same function, keep the function but call it only from `platform_context`, not from tool results.
- The escalation/orchestration-hint advisory formatters (`orchestration_hints.py:format_orchestration_hints`) — if nothing else calls them after Step 1, delete them; keep only `build_orchestration_meta`'s factual-marker path if that's still needed for `next_hint`. Grep to confirm before deleting.
- Earlier audit found `build_situational_brief` was being computed **twice per turn** (once here, once in the system prompt build). Removing it here also removes that redundant double-compute — confirm the system-prompt path still has what it needs from `platform_context`.

### Step 3 — Light audit of the MCP formatter
`_format_exec_result` (`server.py:1057`): confirm it does NOT inject situational brief or escalation nudges (it doesn't, at `d7a4594`). Leave its structure; its only change is Plan 01's truncation swap. Do not add "parity" noise to it.

### Step 4 — Coherence with `platform_context`
Verify `platform_context` (the deliberate "where are we" tool) still surfaces phase status / what's-unlocked that the situational brief used to staple onto every result — so the information is *available on demand*, just not forced into every tool return. If a gap exists, add it to `platform_context`, not back into tool results.

## Reconnect summary
Phase/situational awareness moves from "on every tool result" to "on demand via `platform_context`". Factual kernel markers (`next_hint`) stay. Failure diagnostics stay (failure-gated). The driver loses nothing it can't fetch deliberately, and gains a cleaner default tool result.

## Done criteria
- A successful tool result on the backend agent path contains exactly: raw stdout, PARSED SUMMARY, SESSION FINDINGS — no situational brief, no advisory next-tool nudge.
- `next_hint` factual markers still appear when the kernel auto-fell-back or auto-chunked.
- `grep -rn "build_situational_brief" backend` shows it called only from `platform_context` (or not at all if deleted).
- `platform_context` still reports phase status / unlocked phases.
- `cd backend && python -m pytest tests/ -q` passes.
