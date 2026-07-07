# MCP Servers

This directory is reserved for capability-based MCP servers so the planner can stay stable while tools change underneath it.

Planned layout:

- `recon/` for discovery, OSINT, DNS, and target graph expansion
- `network/` for port, service, and TLS enumeration
- `webapp/` for app-layer discovery and content mapping
- `vuln/` for template scanning and version correlation
- `exploit/` for gated exploitation adapters
- `postex/` for authorized post-compromise evidence collection
- `report/` for finding normalization and export
