# MCP Servers

Modular, capability-based MCP servers exposing real CLI pentest tools with typed
signatures. Each category is a standalone **FastMCP** server; tools pair a
`build_command()` recipe with a typed `run()` signature, executed through `_core`
(no HTTP hop, no `shell=True`).

> Attribution for reused third-party command-builder recipes and error-handling
> logic is recorded in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Catalog (87 tools + nmap)

Only **real CLI pentest tools** are exposed — not AI helpers, dashboards, or server ops.

| Category | Tools | Examples |
|---|---:|---|
| **recon** | 9 | subfinder, amass, httpx, gau, waybackurls, hakrawler, dnsenum, fierce, autorecon |
| **network** | 12 + nmap | rustscan, masscan, netexec, smbmap, enum4linux-ng, responder, rpcclient |
| **web** | 22 | gobuster, ffuf, sqlmap, nikto, katana, dalfox, zap, wfuzz, dirb |
| **vuln** | 2 | nuclei, jaeles |
| **cloud** | 12 | prowler, trivy, kube-hunter, checkov, scout-suite, pacu |
| **creds** | 3 | hydra, hashcat, john |
| **exploit** | 3 | metasploit, msfvenom, pwntools |
| **api** | 3 | api_fuzzer, graphql_scanner, api_schema_analyzer |
| **binary** | 15 | gdb, ghidra, angr, radare2, ropgadget, checksec |
| **forensics** | 6 | volatility, foremost, exiftool, steghide, hashpump |

**Hero nmap (3):** `nmap_syn_scan`, `nmap_service_scan`, `nmap_custom_scan` — command
building is special-cased in the backend's `command_builder.py::_build_nmap_command`
(handles unprivileged-container flag rewriting), not routed through a per-tool
`tools/*.py` adapter here.

**Total MCP-exposed tools: 90** (87 catalog + 3 nmap).

### Deliberately excluded

| Excluded | Why |
|---|---|
| AI wrappers, bug-bounty workflows, telemetry, `execute_command`, file/process ops | Not pentest tools — the platform provides these as governed primitives, not catalog tools |
| `jwt_analyzer` | Pure Python logic — no CLI binary |
| `nmap_scan`, `nmap_advanced_scan` | Superseded by the `command_builder.py` nmap special-case |

## Layout

```
mcp-servers/
  _core/           # executor, cache, error_handler, runner, result
  recon/           tools/*.py  server.py
  network/         tools/*.py  server.py
  web/
  vuln/
  cloud/
  creds/
  exploit/
  api/
  binary/
  forensics/
```

## Per-tool module pattern

| Piece | Role |
|---|---|
| `TOOL_NAME`, `CATEGORY` | Tool identity |
| `build_command(**params)` | Assemble the CLI invocation from typed params |
| `run(...)` | Typed params + `exec_timeout` |
| `parse(result)` | Stub — Summary Agent / graph parsers go here |

## Run a category server

```bash
pip install -r mcp-servers/requirements.txt
python mcp-servers/network/server.py
python mcp-servers/web/server.py
```

Run inside **Kali WSL** or a Docker image where the underlying binaries exist.

## OpenCode / Claude Desktop

```json
{
  "mcpServers": {
    "pentest-network": {
      "command": "python",
      "args": ["mcp-servers/network/server.py"]
    },
    "pentest-web": {
      "command": "python",
      "args": ["mcp-servers/web/server.py"]
    }
  }
}
```

## Error handling (Escalation Matrix)

`_core/error_handler.py` provides an intelligent recovery loop:

- Regex error classification (timeout, permission, rate limit, tool not found, …)
- Recovery strategy selection per error type
- Retry with backoff, parameter auto-adjustment per tool, alternative-tool lookup
- Human escalation payload with suggested actions
- Graceful-degradation fallback chains for partial failures

**Summary Agent integration** — before writing a failed tool result to the graph:

```python
from _core import process_tool_failure

decision = process_tool_failure(
    tool_name="nmap_service_scan",
    error_message=result["stderr"],
    parameters=params,
    target="10.0.0.1",
    attempt_count=1,
)
# decision["recovery_action"] → retry_with_backoff | switch_to_alternative_tool | escalate_to_human | ...
# decision["alternative_tool"], decision["adjusted_parameters"], decision["human_escalation"]
```

MCP tools pass `use_recovery=True` to `run_tool()` to apply the full loop automatically.

## Next steps (orchestrator)

1. Per-tool `parse()` → graph nodes for Summary Agent
2. FastAPI MCP client wiring by engagement phase
