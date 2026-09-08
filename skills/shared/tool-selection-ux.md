---
name: tool-selection-ux
description: "For the Commander when planning: state each tool with one-line reasoning and which coverage gap it closes; trust the LLM to pick flags (there is no command-preview round-trip)."
phases: [shared]
tags: [methodology, commander]
---

# Tool Selection (for Commander)

When planning, state for each step:
1. Tool name and one-line reasoning
2. What gap in the graph/coverage it closes

Trust the LLM to pick flags — there is no command-preview round-trip. The backend
validates and normalizes before running; a bad command fails fast with a clear error.

Execution and memory:
- `POST /api/v1/mcp/execute` — run a tool (`tool_name`, `params`, `additional_args`, `run_id`)
- `GET /api/v1/hybrid/context/{phase}` — findings, gaps, graph, pivots, tool catalog
