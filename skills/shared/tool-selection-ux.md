# Tool Selection UX (for Commander)

Before execution, show the user:
1. Tool name and one-line reasoning
2. Built command preview (optional: `POST /api/v1/capabilities/build-command`)
3. ~5 second override window to cancel or edit

Catalog endpoints:
- `GET /api/v1/capabilities/phases/{phase}/llm-catalog` — tools + tasks for function calling
- `GET /api/v1/capabilities/skills/{phase}` — markdown skills for system prompt

Execution:
- `POST /api/v1/mcp/execute` with `tool_name`, `params`, `additional_args`, `engagement_id`, `run_id`

Memory between turns:
- `GET /api/v1/findings/summary?engagement_id=...&run_id=...`
