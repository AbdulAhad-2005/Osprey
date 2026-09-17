> **HISTORICAL — NOT DESIGN AUTHORITY.** This re-scoped ticket predates the
> heuristic-engine design, and that design itself was later abandoned and
> deleted (`heuristic-engine-flow.md` / `config/heuristic-engine.yaml` no
> longer exist) in favor of one un-caged harness: the driver decides tool
> order, chaining, and prioritization from raw evidence; hard gates are
> reserved for genuine RoE/authorization boundaries and resource-safety caps
> (see `plans/README.md`). In particular, item 2 under "Lessons Learned"
> below (honeypot detection, scope validation, parameter-reflection gate) was
> **not** carried forward — those were dropped as unnecessary gatekeeping,
> not rebuilt. Kept only as a record of the reasoning trail, not a spec.

# Issue #18: Commander/CLI Evolution + AI Harness Integration (RE-SCOPED)

> **Re-scoped based on:**
> - Deep analysis of 15 operational failure modes blocking LLM effectiveness
> - LLM usability analysis (6 categories of problems)
> - Complete reading of 80 skill files across 21 directories
> - Strix pattern analysis (6 patterns to adopt, 7 gaps Osprey fills)
> - User directive: "The deterministic systems were hurdles that were kept on adding. The LLM should decide what to do from findings. Keep knowledge, delete gates."
> - Comprehensive pentest flow design document (`docs/pentest-flow-design.md`)

---

## Corrected Architecture

### What Stays (Knowledge)
- **80 skill files** in `skills/` — these are GUIDANCE for LLM agents AND INSTRUCTIONS for the heuristics engine
- **Playbooks** (`config/playbooks.yaml`) — advisory tool sequences
- **Escalation playbook** (`shared/escalation-playbook.md`) — what to try when tools fail
- **Findings store, graph, memory** — the communication layer between phases

### What Gets Deleted (Gates)
- **Sufficiency thresholds** (`sufficiency.py` `_DEFAULTS`) — too conservative, single-host targets never reach vuln phase
- **Turn urgency** (`phase_agent.py` `_TURN_URGENCY_BANDS`) — truncates exploration at 70%
- **Situational anchoring** (`situational_context.py` "SENSIBLE NEXT MOVES" / "LIKELY NOT WORTH DOING NOW") — makes decisions for the LLM
- **Auto-fallback** (`phase_supervisor.py` auto-fallback logic) — LLM unaware of tool substitution
- **Escalation dead code** (`escalation_matrix.yaml` signals `count_lt_5`, `port_445_open`, `port_139_open`) — never produced by detection

### What Gets Built
- **Conductor**: simple role assignment based on findings (recon/vuln/exploit), no thresholds
- **3 agent roles**: recon, vuln, exploit — each with a brief (goals), not a script (tool list)
- **Flow definitions**: YAML serving both paths (LLM reads as guidance, heuristics engine parses as instructions)
- **LLM usability fixes**: remove information loss, contradictory instructions, false signals

---

## Scope Items

### 1. Conductor Simplification
**Files:** `backend/src/osprey/services/sufficiency.py`, `backend/src/osprey/services/phase_supervisor.py`

| Change | File | Lines | Detail |
|--------|------|-------|--------|
| Delete thresholds | `sufficiency.py` | 25-34 | Remove `_DEFAULTS` dict entirely |
| Simplify `should_trigger()` | `sufficiency.py` | 78-88 | Replace threshold logic with: "any finding of the right type unlocks the phase" |
| Simplify `phase_signals()` | `sufficiency.py` | 64-75 | Keep counting, remove threshold comparison |
| Remove auto-fallback | `phase_supervisor.py` | ~154 | Remove `sufficiency.should_trigger()` call, replace with simple finding-type check |

**New conductor logic:**
```python
# Vuln unlocks when ANY live host, service, technology, or URL exists
if phase == "recon" and findings.has_any(type=["host", "service", "technology", "url"]):
    transition_to("vuln")

# Exploit unlocks when ANY vulnerability, credential, or secret exists
if phase == "vuln" and findings.has_any(type=["vulnerability", "credential", "secret"]):
    transition_to("exploit")
```

**Effort:** 1 day

### 2. Agent Role Implementation
**Files:** `backend/src/osprey/services/phase_agent.py`, new file `backend/src/osprey/services/agent_roles.py`

| Change | File | Lines | Detail |
|--------|------|-------|--------|
| Delete turn urgency | `phase_agent.py` | 665-669 | Remove `_TURN_URGENCY_BANDS` entirely |
| Delete situational anchoring | `situational_context.py` | 147-155 | Remove "SENSIBLE NEXT MOVES" and "LIKELY NOT WORTH DOING NOW" sections |
| Fix findings truncation | `phase_agent.py` | 739 | Remove `[:1400]` cap, use full findings |
| Fix contradictory prompts | `phase_agent.py` | 209-251 | Remove duplicate identity definitions from `_COMMANDER_SYSTEM` and `_PHASE_SYSTEM` |
| Create role briefs | new `agent_roles.py` | — | 3 role definitions with briefs (goals), not scripts |

**Agent role briefs (from `docs/pentest-flow-design.md`):**
- **Recon brief:** "Map the full attack surface. Seed with whois/domain_hunter, enumerate subdomains, probe live hosts, resolve to IPs, discover ports, version-scan, attribute CDN/WAF, crawl web apps, fingerprint tech, harvest OSINT. Every new asset gets expanded. Stop when a full pass adds nothing new."
- **Vuln brief:** "Probe discovered services and web apps for known vulnerabilities, misconfigs, exposed credentials, and injection points. Start with nuclei on every live web host. Then nikto, wpscan, sqlmap, dalfox, nmap vuln scripts, sslyze, graphql_cop. Every finding needs observed proof before CRITICAL/HIGH claims."
- **Exploit brief:** "Validate vulnerability findings, attempt exploitation within scope, establish access. Search CVEs first (searchsploit), then metasploit. Test credentials against all services. Crack hashes offline. Prove impact with PoC — shell banner, one file read, login confirmed."

**Effort:** 3 days

### 3. Flow Definitions
**New files:** `config/flows/recon.yaml`, `config/flows/vuln.yaml`, `config/flows/exploit.yaml`, `config/flows/shared.yaml`

YAML flow definitions derived from 80 skill files. Each flow definition serves both paths:
- LLM reads it as guidance (prose descriptions)
- Heuristics engine parses it as instructions (tool names, parameters, conditions)

**Flow structure per `docs/pentest-flow-design.md` Section 5:**
```yaml
phase: recon
role: recon
goal: "Map the full attack surface"
termination:
  strategy: fixpoint
  metric: new_findings_last_run
  threshold: 0
  window: 2
tools:
  - name: subfinder_scan
    purpose: "Fast passive subdomain enumeration"
    condition: always
    order: 1
    params:
      domain: "{{target}}"
  - name: amass_scan
    purpose: "Deep passive enumeration"
    condition: "subfinder.results_count < 5"
    order: 1
    priority: escalation
    params:
      domain: "{{target}}"
      additional_args: "-passive"
  # ... (full catalog from docs/pentest-flow-design.md)
```

**Effort:** 5 days

### 4. LLM Usability Fixes
**Files:** `backend/src/osprey/services/summary_agent.py`, `backend/src/osprey/services/param_validator.py`, `backend/src/osprey/platform/situational_context.py`, `cli/agent/context.py`

| Change | File | Lines | Detail |
|--------|------|-------|--------|
| Remove findings truncation | `phase_agent.py` | 739 | Delete `[:1400]` cap |
| Remove CLI truncation | `summary_agent.py` | 37 | Increase `_MAX_STDOUT_FOR_LLM` from 12000 to 30000 |
| Remove item caps | `summary_agent.py` | 303 | Remove `[:25]` cap on key_facts |
| Fix shell metachar regex | `param_validator.py` | 19 | Allow `$` in param values (legitimate in URLs, env vars), block only in freeform_args |
| Remove dead escalation signals | `escalation_matrix.yaml` | 17, 131 | Remove `count_lt_5`, `port_445_open`, `port_139_open` from signal lists |
| Fix config cache staleness | Multiple | — | Add `cache_clear()` calls on engagement switch |
| Fix fixpoint detection | `phase_supervisor.py` | — | Track per-phase new findings, not total |
| Fix spawned worker context | `phase_agent.py` | — | Pass system prompt and context to spawned workers |
| Remove contradictory identity | `phase_agent.py` | 209-251 | Single consistent identity definition |

**Effort:** 3 days

### 5. CTF Integration
**Files:** `cli/commands/ctf.py` (new), `cli/agent/loop.py`, `cli/agent/tools.py`

| Change | Detail |
|--------|--------|
| New `/ctf` command | Entry point for CTF mode with challenges.json config |
| Challenge loader | Parse challenge config, set target, load context |
| CTF-specific tool catalog | Restrict to CTF-relevant tools (no OSINT, no recon widening) |
| Flag capture detection | Hook into findings store for flag format patterns |
| Timer/progress | Track time per challenge, show progress |

**Effort:** 5 days

### 6. AI Harness Integration (Strix Pattern)
**Files:** `backend/src/osprey/services/agent_roles.py` (new), `backend/src/osprey/services/phase_agent.py`

| Change | Detail |
|--------|--------|
| Role-based agent spawning | Conductor assigns role → agent gets brief + context |
| Single runner pattern | One ReAct loop per agent, no nested loops |
| Session resume | `platform_context` + `platform_findings` restore state |
| Budget management | Token budget per agent, not per turn |

**Effort:** 3 days (overlaps with #2)

### 7. Memory Integration
**Files:** `backend/src/osprey/services/cognee_client.py` (new), `backend/src/osprey/services/honcho_client.py` (new)

| Change | Detail |
|--------|--------|
| Cognee | Evaluate against existing graph; default is keep current |
| Honcho | Integrate as external self-hosted service via API (AGPL-3.0 compliant) |
| Villager | Research reference only — never download/install/clone/execute |

**Effort:** 5 days

### 8. VAPT Module Completion
**Files:** Flow definitions (item #3), conductor (item #1), agent roles (item #2)

The "VAPT module" is not a discrete module — it's the orchestration of existing tools. What's missing:
- Flow definitions (item #3)
- Conductor logic (item #1)
- Agent roles (item #2)
- Entry points (`/scan`, `/vuln`, `/exploit` commands)

**Effort:** Covered by items #1-3

### 9. Testing & Documentation
| Change | Detail |
|--------|--------|
| Unit tests | Conductor phase transitions, flow definition parsing, role assignment |
| Integration tests | Full recon→vuln→exploit pipeline on test target |
| E2E tests | CLI `/scan` command end-to-end |
| Documentation | Update AGENTS.md, skill authoring guide, CLI help |

**Effort:** 3 days

---

## Effort Summary

| # | Scope Item | Effort | Dependencies |
|---|-----------|--------|--------------|
| 1 | Conductor Simplification | 1 day | — |
| 2 | Agent Role Implementation | 3 days | #1 |
| 3 | Flow Definitions | 5 days | — |
| 4 | LLM Usability Fixes | 3 days | — |
| 5 | CTF Integration | 5 days | #2 |
| 6 | AI Harness Integration | 3 days | #2 (overlaps) |
| 7 | Memory Integration | 5 days | — |
| 8 | VAPT Module Completion | — | Covered by #1-3 |
| 9 | Testing & Documentation | 3 days | All above |
| **Total** | | **28 days** | |

Parallelizable: #1, #3, #4, #7 can run in parallel. #2 depends on #1. #5, #6 depend on #2. #9 depends on all.

---

## Key Design Decisions

1. **Knowledge stays, gates go**: 80 skill files remain as guidance. Sufficiency thresholds, turn urgency, situational anchoring, auto-fallback are deleted.
2. **Role-based, not script-based**: Agents get briefs (goals), not tool lists. The conductor assigns roles; agents decide their own tools.
3. **Dual-path flow definitions**: YAML serves both LLM (guidance) and heuristics engine (instructions).
4. **Simple conductor**: No thresholds. "Any finding of the right type unlocks the next phase."
5. **Findings as communication**: Agents never talk to each other. Findings store is the only channel.
6. **No forking/vendoring**: Full IP ownership. MCP tool layer is the sole integration contract.

---

## Reference Documents

- **Pentest flow design**: `docs/pentest-flow-design.md` (1332 lines, 52KB) — complete specification
- **Original analysis**: Previous conversation with 15 operational failure modes documented
- **Strix patterns**: `D:\personal work\AI-Pentesting-Tool\llmwork\strix\strix\strix\core\runner.py` — single runner reference
- **Skill files**: `skills/` directory — 80 files across 21 directories

---

## Lessons Learned (Post-Design)

1. **3-phase model was too coarse** — P2.5 (Threat Modeling) and P3.0 (Manual App Mapping) are critical pre-exploitation phases that prevent the "sqlmap at .jpg URLs" failure.
2. **Gate deletion was the right call** — but replacing them with zero gates left no filtering. The fix: mechanical P3→P4 filters (static asset exclusion, content-type filter, parameter reflection gate, minimum evidence gate, honeypot detection, scope validation).
3. **Sufficiency thresholds were hostile** — single-host web apps never reach vuln phase. Deleted entirely.
4. **Findings inflation** — single nmap scan produces 30+ findings. LLM sees "47 findings" when real info is "10 ports, 10 services". Needs deduplication at ingestion.
5. **Exploitation tiers prevent waste** — Tier 1 (pattern proof, 60s) before Tier 3 (full exploit, 900s) saves hours.
6. **"No Exploit, No Report"** — every finding needs exploitation evidence. POTENTIAL is acceptable; FALSE_POSITIVE is suppressed.
7. **Exhaustion gates prevent premature放弃** — "3 SQLi payloads tested" ≠ "not exploitable". Minimum effort per vulnerability class.
8. **LLM usability blockers** — 14+ validation gates per tool call, 8s docker exec cold-cache, 30s rate governor, 1400-char findings cap, situational anchoring, turn urgency at 70%. All need fixing.
