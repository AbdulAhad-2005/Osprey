# LLM / Commander Integration Guide

Your friend implements the Commander loop, LiteLLM, and chat endpoint. This document describes the **tools layer** you consume.

## Contract: ToolCallProposal

The LLM must never output raw shell. Emit:

```json
{
  "tool_name": "subfinder_scan",
  "reasoning": "Passive subdomain enum on example.com",
  "params": { "domain": "example.com" },
  "additional_args": "-all -recursive",
  "task": "subdomain_enumeration",
  "based_on_findings": []
}
```

### Free-form flags (important)

- **`additional_args` is unrestricted** — any valid CLI flags the model knows.
- Examples in YAML/catalog are **suggestions only**, not an allowlist.
- Platform blocks only shell metacharacters: `;|&`$()<>`
- Flags can also appear inside `params.additional_args`, `extra_args`, or `flags` (nmap) — they are merged automatically.

## API Flow

```
1. GET  /api/v1/capabilities/phases/recon/llm-catalog   # tool schemas
2. GET  /api/v1/capabilities/skills/recon                 # markdown skills → system prompt
3. GET  /api/v1/findings/summary?engagement_id=&run_id=    # prior findings memory
4. POST /api/v1/capabilities/validate                     # optional pre-flight
5. POST /api/v1/capabilities/build-command                # optional preview
6. POST /api/v1/mcp/execute                               # run tool
```

### Execute request body

```json
{
  "tool_name": "subfinder_scan",
  "params": { "domain": "example.com" },
  "additional_args": "-all",
  "engagement_id": "eng-123",
  "run_id": "run-456",
  "record_findings": true,
  "timeout": 300
}
```

Successful runs auto-parse stdout into the findings store (subfinder, httpx, nmap, rustscan, etc.).

## Python helpers (if importing directly)

```python
from pentest_platform.services.task_registry import llm_tool_catalog_for_phase
from pentest_platform.services.skills_loader import load_skills_for_phase
from pentest_platform.services.param_validator import validate_tool_call
from pentest_platform.services.command_builder import build_from_proposal
from pentest_platform.schemas.tool_call import ToolCallProposal
```

## What you build

- Commander agent loop (plan → propose → validate → execute → summarize)
- LiteLLM model routing
- `POST /api/v1/agent/chat` or `/agent/run`
- 5-second tool override UX (see `skills/shared/tool-selection-ux.md`)

## What is already built

- Single `command_builder` (harvested MCP `build_command()` + LLM flags)
- `param_validator` (permissive)
- `task_registry` + `config/recon_network_tools.yaml`
- Skills markdown under `skills/`
- Findings store + parsers
- Capabilities + findings REST endpoints
