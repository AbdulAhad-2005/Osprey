# Integration Contract — MCP & HTTP API surface

> **Purpose:** The stable surfaces between the LLM (OpenCode / any MCP client), the `platform-mcp` gateway, and the FastAPI backend. Code against these — not against recon/network-specific internals.
> **Related:** [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) · [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md)

## Principles

- **Assist the LLM, don't script it** — YAML, skills, and hints are suggestions; only safety is hard-enforced.
- **One kernel for all phases** — execution, parsing, and memory live in the backend; new phases register parsers/hints instead of forking driver logic.
- **The LLM never sends raw shell** — it sends structured tool calls, an allowlisted single binary (`platform_shell`), or a sandboxed script (`platform_script`). The platform builds the CLI.

---

## 1. MCP surface (what the LLM calls)

The LLM talks only to `platform-mcp/server.py` over stdio. It never touches `mcp-servers/*` directly — those are Kali-side, reached through the backend. Tool families:

| Family | Tools |
|--------|-------|
| **Session** | `platform_set_target`, `platform_delete_engagement`, `platform_health` |
| **Memory / notebook** | `platform_context`, `platform_think`, `platform_thinking`, `platform_graph_link[_many]`, `platform_graph_query`, `platform_tag_asset`, `platform_crown_jewels`, `platform_findings`, `platform_record_finding`, `platform_memory_search`, `platform_evidence_chain`, `platform_attempts`, `platform_artifact` |
| **Report** | `platform_finalize_check`, `platform_report_outline` |
| **Execution** | 36 typed `*_scan` / `*_probe` tools, `platform_exec`, `platform_shell`, `platform_script`, `platform_install` |
| **Async / batch** | `platform_job_start`, `platform_job_poll`, `platform_job_result`, `platform_fanout`, `platform_fanout_assets` |
| **Advisory / config** | `platform_tools`, `platform_skills`, `platform_config`, `platform_playbook` |

Per-tool semantics are documented in [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md). Client wiring (OpenCode / Claude Desktop / ChatGPT) is in the root [`README.md`](../README.md).

### Free-form flags (first-class)

- **`additional_args` is unrestricted** — any valid CLI flags the model knows. Catalog/YAML examples are suggestions, not an allowlist.
- The platform blocks only shell metacharacters: `` ; | & ` $ ( ) < > ``.
- Flags may also arrive inside `params.additional_args`, `params.extra_args`, or `params.flags` (nmap) — they are merged automatically.
- Pipes / loops / compound shell → use `platform_script`, not shell metacharacters.

---

## 2. Backend HTTP surface (what platform-mcp calls)

Base: `http://localhost:9000`. Registered under `/api/v1` (`api/v1/router.py`).

### Execution — `/api/v1/mcp/*`
| Route | Body → | Purpose |
|-------|--------|---------|
| `POST /mcp/execute` | `ToolExecutionRequest` | Run a catalog tool through the kernel |
| `POST /mcp/shell` | `{command, engagement_id, run_id, reason, timeout}` | One allowlisted binary + argv |
| `POST /mcp/script` | `{code, language, engagement_id, packages, timeout}` | Write + run a script in the engagement workspace |
| `POST /mcp/install` | `{manager, packages, engagement_id}` | Gated pip/apt install for script deps |

`ToolExecutionRequest` (`schemas/tools.py`):
```json
{
  "tool_name": "subfinder_scan",
  "params": { "domain": "example.com" },
  "additional_args": "-all -recursive",
  "engagement_id": "eng-123",
  "run_id": "run-456",
  "record_findings": true,
  "use_recovery": true,
  "use_cache": true,
  "force_refresh": false,
  "timeout": 300
}
```
`ToolExecutionResponse` returns: `tool_name`, `success`, `stdout`, `stderr`, `command`, `returncode`, `duration_seconds`, `timed_out`, `error`, `finding_titles`, `governance_decision`, `cache_hit`, `cache_key`, `next_hint`, `fallback_tools`, `hybrid` (escalation/dispatch/graph pivots + artifact paths). Successful runs auto-parse stdout into findings; raw stdout/stderr is always preserved (parse miss ≠ nothing found).

### Memory / notebook — `/api/v1/hybrid/*`
The backing routes for the `platform_*` memory tools. Key ones: `GET /hybrid/context[/{phase}]`, `GET /hybrid/coverage/{phase}`, `GET /hybrid/open-loops`, `POST /hybrid/correlate`, `GET /hybrid/graph/{summary,siblings,query}`, `POST /hybrid/graph/{link,link-many}`, `POST /hybrid/tag-asset`, `POST /hybrid/think`, `GET /hybrid/crown-jewels`, `GET /hybrid/finalize-readiness`, `GET /hybrid/report-outline`, `GET /hybrid/memory-search`, `GET /hybrid/evidence-chain`, `GET /hybrid/attempts`.

### Engagements & jobs
- `POST /api/v1/engagements/resolve` (bind/create by target), `POST /{id}/runs/ensure`, `POST /{id}/actions/enumerate-pending-sisters`, `POST /{id}/actions/fanout-assets`, `DELETE /by-target`, `DELETE /{id}`.
- `POST /api/v1/jobs/start`, `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `GET /api/v1/jobs/{id}/result`.

### Deprecated routes (do not use for new callers)
Use `platform_context` / `platform_attempts` / catalog instead:
`GET /api/v1/tools/{name}`, `GET /api/v1/tools/by-server/{server}`, `GET /api/v1/engagements/{id}/tree`, `GET /api/v1/engagements/{id}/network-surface`, `GET /api/v1/engagements/{id}/tool-coverage`. Services stay; only the HTTP routes are legacy.

---

## 3. Extending the platform (registration points)

New capability = data + registration, not driver forks.

- **New parser** — `register_output_parser(tool, fn)` / `register_output_digester(...)` in a module imported by `services/parsers/__init__.py`.
- **New failure hint** — `register_hint_provider(fn, priority=…)` in `platform/hint_providers.py`.
- **New tool** — add the `build_command()` wrapper under `mcp-servers/<category>/tools/`, register it in the catalog, and (optionally) expose a typed MCP tool in `platform-mcp/`.
- **New ingest pattern** — add a regex to `config/ingest_rules.yaml` (no code, no AGENTS bullet).

---

## 4. Opt-in internal surface (Executor B)

The built-in Commander path (`services/phase_agent.py`, `services/commander_pipeline.py`, `services/orchestrator.py`, `POST /api/v1/agent/chat[/stream]`, SSE events) is **off by default** (`enable_builtin_agent=false`). It reuses the same execution kernel. Documented here only so it is not mistaken for the default contract; prefer the MCP + HTTP surfaces above.

---

*Surfaces above are the join points. The MCP + `/mcp/*` + `/hybrid/*` routes are the current product contract; everything under path ② is optional.*
