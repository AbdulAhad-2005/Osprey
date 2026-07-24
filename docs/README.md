# Documentation Index

Docs for the **AI Pentesting Tool** — an autonomous AI penetration-testing platform where an external LLM (OpenCode) is the brain and the platform is a lab + referee + shared notebook. Current build covers **recon + network / enum**.

Start here based on what you need:

| If you want to… | Read |
|-----------------|------|
| Understand how it works and why | [`ARCHITECTURE.md`](./ARCHITECTURE.md) |
| Run and operate the platform | [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) |
| Modify the code (read-order, pipeline trace, optimization) | [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md) |
| Look up a specific tool / memory capability | [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) |
| Integrate against the MCP / HTTP APIs | [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) |
| See what's built vs planned | [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md) |
| See the full future vision | [`HYBRID_PLATFORM_BLUEPRINT.md`](./HYBRID_PLATFORM_BLUEPRINT.md) |

## Documents

### Current architecture & usage
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — *Everyone.* Concepts, the four roles (lab/notebook/referee/brain), primary vs demoted path, prompt→command flow, design decisions.
- **[PLATFORM_GUIDE.md](./PLATFORM_GUIDE.md)** — *Operators.* How to run it, tool preference order, memory/graph/findings, evidence grades, finalize gate, MCP tool cheat sheet.
- **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)** — *Developers.* Code exploration map, end-to-end pipeline trace, recommended read-order, what's hard-enforced vs soft.
- **[CAPABILITY_REFERENCE.md](./CAPABILITY_REFERENCE.md)** — *Developers/operators.* Implementation-level reference for the `platform_*` tools, memory/graph, evidence law, jobs, scripts (Elite-Operator Phases 1–7).
- **[ELITE_PLATFORM_MEMORY_AND_CALL_FLOW.html](./ELITE_PLATFORM_MEMORY_AND_CALL_FLOW.html)** — *Visual companion.* Rendered walkthrough of how memory/graph are stored in Postgres, what every `platform_*` tool does, and the complete engagement call flow (open in a browser).
- **[INTEGRATION_CONTRACT.md](./INTEGRATION_CONTRACT.md)** — *Integrators.* MCP tool families + backend HTTP surface (`/api/v1/mcp/*`, `/api/v1/hybrid/*`, engagements, jobs), request/response schemas, extension points.

### Status, roadmap & vision
- **[STATUS_AND_ROADMAP.md](./STATUS_AND_ROADMAP.md)** — What's done (Phases 1–7), what's active (reliability plan), what's next (memory query-back, phase expansion, killchain).
- **[HYBRID_PLATFORM_BLUEPRINT.md](./HYBRID_PLATFORM_BLUEPRINT.md)** — Forward-looking north-star vision synthesizing Shannon / Shannon-plugin / Dark-Moon / HexStrike into the full-lifecycle platform.

### Plans (`plans/`)
- **[plans/ELITE_OPERATOR_PHASED_PLAN.md](./plans/ELITE_OPERATOR_PHASED_PLAN.md)** — "What's done": the completed Phases 1–7 (writable + searchable memory).
- **[plans/ELITE_RELIABILITY_IMPLEMENTATION_PLAN.md](./plans/ELITE_RELIABILITY_IMPLEMENTATION_PLAN.md)** — "What's next": the active 9-phase delta plan hardening reliability, safety, provenance.

### Archive (`archive/`)
Historical material kept for reference, not maintained: the original Cursor build log (`cursor_nmap_custom_wrapper.md`), OpenCode gap analysis (`opencode_analysis.txt`), scratch notes (`codes.txt`), and legacy design `.docx` notes under `legacy-design-notes/`.

## Related material outside `docs/`
- **[../AGENTS.md](../AGENTS.md)** — the OpenCode operator prompt (the LLM's actual instructions).
- **[../README.md](../README.md)** — setup, quickstart, and MCP client configuration.
- **[../config/README.md](../config/README.md)** — the YAML "referee" config (catalog, escalation, ingest, thinking model).
- **[../mcp-servers/README.md](../mcp-servers/README.md)** · **[../mcp-servers/network/README.md](../mcp-servers/network/README.md)** — tool-wrapper layer.
- **[../Comparative Analysis/](../Comparative%20Analysis/)** — HTML deep-dives of the four reference tools + `tools.json`.
- **[../Pentest-Reports/](../Pentest-Reports/)** — reference-tool report outputs + a real engagement report.
