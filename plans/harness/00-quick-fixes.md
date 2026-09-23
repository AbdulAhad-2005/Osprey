# Plan 00 — Quick fixes (stop the bleeding)

**Baseline:** `10d13ae` · **Risk:** Low · **Depends on:** nothing · **Size:** ~1 day.

Two verified, live defects that are cheap to fix and unblock everything else. Do these
before any architecture work so the benchmark in Plan 01 runs against a non-crashing base.

## Fix A — `/agent` and custom-command expansion crash (`ImportError`)

**Verified:** `cli/commands/slash.py:980` (`from cli.agent.flows import load_agents`) and
`:1066` (`from cli.agent.flows import expand_command, load_commands`) import a module that
does not exist — `cli/agent/` has no `flows.py`. Any `/agent`, `/agent <name>`, or custom
slash-command expansion raises `ImportError` at call time.

### Decision first (do not guess)
Grep the tree for what `load_agents`, `expand_command`, `load_commands` are expected to
return and who consumes `client.active_agent`. The feature (prompt-defined agent modes from
`.osprey/agents/<name>.md`, per the `handle_agent` docstring) is clearly intended and is the
same mechanism Plan 08 (skills at scale) and Plan 09 (dual-mode) will lean on for
subagent tool-scoping. So **build the module**, do not delete the imports.

### Steps
1. Create `cli/agent/flows.py` implementing:
   - `load_agents() -> dict[str, Agent]` — read `.osprey/agents/*.md`, parse frontmatter
     (`description`, `tools`, `deny_tools`), body = the mode's system-prompt overlay. Reuse
     `knowledge_browser.parse_frontmatter` rather than re-implementing a parser.
   - `load_commands() -> dict[str, Command]` and `expand_command(name, args) -> str` — read
     `.osprey/commands/*.md`, expand `$ARGUMENTS`/`$1..$n` placeholders.
   - An `Agent` dataclass (`name`, `description`, `tools`, `deny_tools`, `system_overlay`).
2. Wire `deny_tools`/`tools` into the tool scope the runner builds (the runner already
   supports per-agent tool scoping — confirm the field name on the `Runner`/`APIClient`).
3. Add a test: `handle_agent(["list"], client)` runs without raising when
   `.osprey/agents/` is empty and when it has one file.

### Done criteria
- `/agent`, `/agent <name>`, `/agent default` run without `ImportError`.
- A `.osprey/agents/recon.md` with `deny_tools: metasploit_*, hydra_*, sqlmap_*` actually
  removes those tools from the next prompt's catalog.

## Fix B — `Finding.confidence` defaults to `CONFIRMED`

**Verified:** `backend/src/osprey/schemas/finding.py:91` →
`confidence: FindingConfidence = FindingConfidence.CONFIRMED`. Any `Finding(...)` built
without an explicit `confidence` is born CONFIRMED. This is the schema-level form of the
"single observation = confirmed" trap.

### Steps
1. Flip the default to `FindingConfidence.HYPOTHESIS`.
2. This will (correctly) surface every call-site that was silently relying on CONFIRMED.
   Audit the ~96 `Finding(...)` constructions in `parsers/` and the operator-memory/graph
   paths: where a value was genuinely proven (e.g. a validated credential), set
   `confidence=CONFIRMED` **explicitly**; everywhere else, leave the new honest default.
3. Do **not** add a compatibility shim or a migration that re-asserts CONFIRMED — the whole
   point is that CONFIRMED must be reached, never defaulted.
4. Update tests that asserted the old default.

### Reconnect
- `findings_store` grouping/upgrade logic already tracks "strongest confidence" (from the
  prior evidence-grade removal work) — confirm it still upgrades correctly when the floor is
  now HYPOTHESIS.
- Report outline / handoff dossier confidence buckets already read `confidence` — no change.

### Done criteria
- `Finding(finding_type=..., title=...)` with no `confidence` yields `HYPOTHESIS`.
- `grep -n "confidence=FindingConfidence.CONFIRMED" backend/src/osprey/services/parsers` returns
  only sites with a written justification (proven extraction/validated credential), not bulk defaults.
- Backend test suite collects and the confidence-related tests pass.

> Note: Fix B is deliberately shallow here — Plan 03 replaces the whole finding-creation
> pathway. Fix B just stops the bleeding until then; it is not the real fix.
