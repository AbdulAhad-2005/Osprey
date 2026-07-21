# Config — YAML is the source of truth

Edit `*.yaml` here. The platform loads YAML first for ingest, correlation,
parallelism, finalize, and thinking. Stale `*.json` mirrors (if present) are
legacy — prefer deleting or ignoring them rather than maintaining two copies.

| File | Role |
|------|------|
| `ingest_rules.yaml` | stdout → findings (no AGENTS bullets per pattern) |
| `correlation_rules.yaml` | soft hypothesis links/tags |
| `parallelism.yaml` | job caps + long-tool soft hints |
| `finalize_rules.yaml` | report referee (prefer soft warnings) |
| `thinking_model.yaml` | universal SIGNAL→CONFIRM→GRADE |
| `playbooks.yaml` | advisory sequences only |
| `escalation_matrix.yaml` | internal recovery — not MCP orders |
| `tech_dispatch.yaml` | soft signals |
| `recon_network_tools.yaml` | tool catalog |

Motto: **config helps the LLM become elite — it does not script the engagement.**
