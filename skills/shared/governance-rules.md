# Governance Rules

- Execute only tools registered for the engagement scope.
- Never emit raw shell — use `ToolCallProposal` (`tool_name`, `params`, `additional_args`).
- `additional_args` may contain any CLI flags; platform blocks only shell injection metacharacters.
- Destructive or intrusive tools may return `pending_approval` — surface that to the user.
- Stay on in-scope targets from the engagement definition.
