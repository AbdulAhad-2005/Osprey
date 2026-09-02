# Status & Roadmap

> **Purpose:** One place to see **what is built, what is in progress, and what is next.**
> **Scope of current build:** recon, network/enum, web, vuln, exploit, and osint phases, driven by an external MCP harness (default) or the opt-in built-in Commander.

---

## 1. Snapshot

| Layer | State |
|-------|-------|
| OpenCode-as-brain via `platform-mcp` (~50 MCP tools) | ✅ primary path, working |
| Typed tools across recon / network / web / vuln / exploit / osint | ✅ wired + registered, driven by the conductor |
| Execution kernel (exec / shell / script / install / jobs / fanout) | ✅ implemented |
| Findings + engagement graph + evidence-grade severity clamp | ✅ implemented, durable in Postgres |
| Finalize gate (blocks weak/CVE COMPLETE claims) | ✅ implemented |
| Writable + searchable operator memory (graph, hypotheses, evidence chains) | ✅ implemented |
| Built-in Commander (LiteLLM) + CLI | ⚠️ opt-in, off by default (`enable_builtin_agent=false`); external MCP harness is the default driver |
| `mcp-servers/{cloud,binary,forensics,creds,api}` families | ⚠️ wrappers present, **not yet surfaced** as typed MCP tools / skills |
| Governance / scope enforcement | ❌ permissive stub — approves everything |
| Durable jobs + execution-attempt history | ❌ process-local; lost on backend restart |
| Killchain engine · exploit phase · report automation | ❌ not built (vision only) |

---

## 2. What is DONE — Elite Operator Phases 1–7

The platform is a writable, searchable operator notebook. Delivered:

1. **Cognition write APIs** — the LLM authors memory: `platform_graph_link[_many]` (named edges), `platform_tag_asset` (crown-jewel boost), `platform_think` (durable hypotheses), script `FINDING|`/`REL|`/`HYPOTHESIS|` markers.
2. **Quiet suggestions** — open loops are *gaps*, not `try: nmap` orders; context is budgeted (~80 lines); details pulled on demand.
3. **Ingest + correlation** — ~15–20 YAML ingest patterns; cross-finding correlator emits **hypothesis** edges (not observed facts); raw stdout index.
4. **Speed** — background `platform_job_*`, bounded `platform_fanout`, parallel branches (`config/parallelism.yaml`).
5. **Proof & report trust** — evidence-grade clamp, `derived_from` chains, finalize v2, proof-gated `platform_report_outline`.
6. **Hardening** — elite phase test suite (`backend/tests/test_*_phase*.py`), repo hygiene.
7. **Queryable memory** — `platform_memory_search`, `platform_evidence_chain`, `platform_attempts` (advisory, never a ban).

Full detail: [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md).

---

## 3. What is NEXT — active reliability plan

The current active work hardens reliability, safety, provenance, and correctness — it does **not** add features. Highest-impact open items:

| Area | Gap | Reliability phase |
|------|-----|-------------------|
| **Governance** | Approves all tools; GATED / ROE are descriptive, not enforced | 1 |
| **Script budget** | Scripts bypass catalog/shell scan-budget checks | 1 |
| **Durable jobs** | Jobs process-local — restart loses them; no cancellation; no partial-output API | 3 |
| **Attempt history** | `tool_coverage` overwrites `(engagement, tool, asset)` → latest state, not history | 3 |
| **Finding integrity** | Parser + YAML ingest can double-store; counters can diverge | 4 |
| **Graph integrity** | Service/tech nodes disconnected; weak URL/host canonicalization; edges lack provenance | 5 |
| **Correlation** | Auto-writes hypothesis links the LLM can't accept/reject first | 6 |
| **HTTP/SPA classification** | Combined-output classification can demote valid JSON | 7 |
| **Config / deploy** | JSON vs YAML source drift; MCP↔backend route-version drift | 8–9 |

---

## 4. Beyond reliability — product roadmap

Priority order is a proposal, not a commitment.

1. **Memory-as-real-memory / query-back loop.** The graph is written but under-queried. Wanted: a non-hardcoded "checkpoint rhythm at decision boundaries" so the agent revisits graph/hypotheses to probe deeper and avoid stopping early — prerequisite for kill chains.
2. **Open the phase model.** Replace the hard recon|network split with category-driven context so new phases are **skills + allowlist + optional parser**, not new Python services.
3. **Surface the remaining tool families.** Expose `mcp-servers/{cloud,binary,forensics,creds,api}` via typed tools + skills (web/vuln/exploit/osint are already wired).
4. **Killchain engine + exploit agent.** Graph-driven attack-chain design + a governed exploit phase (needs real governance from reliability Phase 1 first).
5. **Report automation.** Evidence-based, confirmed-only reports off the graph.

Design north star: *thin gatekeeper, free thinker, durable memory, open phases — methodology in markdown, not duplicated Python.*

---

## 5. Explicit non-goals

| Non-goal | Why |
|----------|-----|
| Grow `AGENTS.md` with per-error rules / per-vendor skill packs | Burns context; trains a checklist bot |
| A fake "AI decision engine" of static tool scores | The HexStrike trap — rules ≠ reasoning |
| One new Python service per OWASP category | Code explosion; phases should be markdown + allowlist |
| Auto-executing playbooks / mandatory chains | Kills the LLM's free will |
| Deleting evidence grades / scan budget / finalize | Those are the referee — keep them |

---

*Update this file when a roadmap item lands.*
