# Phase 0 — Dead HTTP routes (optional polish)

Services stay. MCP/OpenCode should use hybrid + context, not these metadata routes.

Deprecated for new callers (still present for older tests/UI):

- `GET /api/v1/tools/by-server/{server}` — use `platform_tools` / catalog
- `GET /api/v1/tools/{name}` — use catalog query
- `GET /api/v1/engagements/{id}/tree` — use `platform_context`
- `GET /api/v1/engagements/{id}/network-surface` — use context / open gaps
- `GET /api/v1/engagements/{id}/tool-coverage` — use `platform_attempts`

Do not expand AGENTS with per-route rituals.
