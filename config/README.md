# Config — YAML is the source of truth

Edit `*.yaml` here. The platform loads YAML first for ingest, correlation,
parallelism, finalize, and thinking. Stale `*.json` mirrors (if present) are
legacy — prefer deleting or ignoring them rather than maintaining two copies.

| File | Role |
|------|------|
| `expansion.yaml` | recon stage → tool map (BFS frontier); the engine's stage sequencing |
| `tech_dispatch.yaml` | reactive checks: match an observation → run a tool (the "add your own check" surface) |
| `ingest_rules.yaml` | stdout → observations/findings (no AGENTS bullets per pattern) |
| `correlation_rules.yaml` | soft hypothesis links/tags |
| `priority.yaml` | multi-factor prioritization weights (plans/harness/06) |
| `parallelism.yaml` | job caps + long-tool soft hints |
| `escalation_matrix.yaml` | internal recovery / tool fallback — not MCP orders |
| `playbooks.yaml` | advisory sequences only |
| `*_tools.yaml` | tool catalogs (recon_network / vuln / exploit / osint / breach_intel / custom) |
| `rate_governor.yaml` | per-target pacing + ban detection |
| `parameter_profiles.yaml` | per-tool default flag profiles (stealth/normal) |
| `output_budget.yaml` | response/stdout size budgets |
| `phase_pipeline.yaml` | read-only phase-readiness policy (recon-reopen types); mostly legacy — unlocking now lives in `priority.yaml` |

Motto: **config helps the LLM become elite — it does not script the engagement.**

## Growing the engine yourself — add your own check (no Python)

The highest-value extension is a new deterministic **check**: match on an
observation the engine already records, run a tool, record a candidate. Add it
to `tech_dispatch.yaml` (or, to keep it local and git-ignored, `tech_dispatch
.local.yaml` — the overlay is deep-merged: a new `id` appends, a matching `id`
edits, `disabled: true` removes a built-in). A rule looks like:

```yaml
signals:
  - id: my_service_cve_lookup          # unique id (required)
    match:                             # fires only when these facts exist
      finding_type: service            # an ObservationType the engine recorded
      scope: per_match                 # one opportunity per matching observation
    dispatch:
      default_tool: searchsploit_lookup  # required
      reason: "Versioned service — look up CVE candidates"
      priority: 6
      skill_file: vuln/network-vuln-scan.md   # optional; must resolve if given
      params_from:                     # map the tool's params from obs fields
        query: service                 # details.service → searchsploit query=
```

It appears as a `list_step` opportunity after a hot-reload, no code change.
Rules are **validated on load** (`services/config_validation.py`): a malformed
rule fails loudly naming the offending field, rather than silently no-opping. A
declared `skill_file` that doesn't exist fails CI
(`tests/test_knowledge_links_resolve.py`). Only a read-only (PASSIVE) tool is
auto-run by the no-LLM engine; an intrusive exploit/creds tool stays behind
explicit operator authorization (`services/heuristic_engine.engine_may_autorun`).
