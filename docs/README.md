# Documentation Index

Docs for **Osprey** — an autonomous AI penetration-testing platform where an LLM is the
brain and the platform is a lab + referee + shared notebook. The current build spans
**recon, network/enum, web, vuln, exploit, and osint** phases (their MCP tools are
registered and driven by the conductor).

Start here based on what you need:

| If you want to… | Read |
|-----------------|------|
| Understand how it works and why | [`ARCHITECTURE.md`](./ARCHITECTURE.md) |
| Run and operate the platform | [`PLATFORM_GUIDE.md`](./PLATFORM_GUIDE.md) |
| Modify the code (read-order, pipeline trace) | [`DEVELOPER_GUIDE.md`](./DEVELOPER_GUIDE.md) |
| Look up a specific tool / memory capability | [`CAPABILITY_REFERENCE.md`](./CAPABILITY_REFERENCE.md) |
| Integrate against the MCP / HTTP APIs | [`INTEGRATION_CONTRACT.md`](./INTEGRATION_CONTRACT.md) |
| See what's built vs planned | [`STATUS_AND_ROADMAP.md`](./STATUS_AND_ROADMAP.md) |

## Documents

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — *Everyone.* Concepts, the four roles
  (lab/notebook/referee/brain), the one-conductor/two-executor model, the prompt→command
  flow, and the design decisions behind them.
- **[PLATFORM_GUIDE.md](./PLATFORM_GUIDE.md)** — *Operators.* How to run it, tool
  preference order, memory/graph/findings, evidence grades, the finalize gate, MCP tool
  cheat sheet.
- **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)** — *Developers.* Code exploration map,
  end-to-end pipeline trace, recommended read-order, what's hard-enforced vs soft.
- **[CAPABILITY_REFERENCE.md](./CAPABILITY_REFERENCE.md)** — *Developers/operators.*
  Implementation-level reference for the `platform_*` tools, memory/graph, evidence law,
  jobs, and scripts.
- **[INTEGRATION_CONTRACT.md](./INTEGRATION_CONTRACT.md)** — *Integrators.* MCP tool
  families + backend HTTP surface (`/api/v1/mcp/*`, `/api/v1/hybrid/*`, engagements,
  jobs), request/response schemas, extension points.
- **[STATUS_AND_ROADMAP.md](./STATUS_AND_ROADMAP.md)** — What's done, what's active, and
  what's next (memory query-back, open phase model, killchain engine).

## Related material outside `docs/`
- **[../AGENTS.md](../AGENTS.md)** — thin operator card (always-on LLM instructions).
- **[../AGENTS_REFERENCE.md](../AGENTS_REFERENCE.md)** — full operator contract (on-demand / humans).
- **[../README.md](../README.md)** — setup, quickstart, and MCP client configuration.
- **[../config/README.md](../config/README.md)** — the YAML "referee" config (catalog,
  escalation, ingest, thinking model).
- **[../mcp-servers/README.md](../mcp-servers/README.md)** — the tool-wrapper layer.
