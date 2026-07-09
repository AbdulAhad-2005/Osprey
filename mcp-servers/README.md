# MCP Servers

Modular capability-based MCP servers harvested from [HexStrike](https://github.com/0x4m4/hexstrike-ai) and adapted for this platform.

Each category is a standalone **FastMCP** server. Tools combine HexStrike Flask command-builders with typed `run()` signatures, executed through `_core` (no HTTP hop, no `shell=True`).

## Full harvest (87 + nmap)

All **real CLI pentest tools** from HexStrike are lifted — not AI helpers, dashboards, or server ops.

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

**Hero nmap (3):** `nmap_syn_scan`, `nmap_service_scan`, `nmap_custom_scan` via [`network/nmap_wrapper.py`](network/nmap_wrapper.py) — replaces harvested HexStrike nmap.

**Total MCP-exposed tools: 90** (87 harvested + 3 nmap).

### Not harvested (by design)

| Excluded | Why |
|---|---|
| ~60 MCP entries | AI wrappers, bug-bounty workflows, telemetry, `execute_command`, file/process ops |
| `jwt_analyzer` | Pure Python logic in Flask — no CLI binary |
| `comprehensive_api_audit` | MCP wrapper with no server route |
| `nmap_scan`, `nmap_advanced_scan` | Superseded by `nmap_wrapper.py` |

## Layout

```
mcp-servers/
  _core/           # executor, cache, error_handler, runner, result
  recon/           tools/*.py  server.py
  network/         tools/*.py  server.py  nmap_wrapper.py  nmap_tools.py
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

| Piece | Source |
|---|---|
| `TOOL_NAME`, `CATEGORY` | HexStrike MCP name |
| `build_command(**params)` | Flask route (auto) or `hexstrike_manual_tools.py` (script/temp-file routes) |
| `run(...)` | Typed params + `exec_timeout` |
| `parse(result)` | Stub — Summary Agent / graph parsers go here |

## Run a category server

```bash
pip install -r mcp-servers/requirements.txt
python mcp-servers/network/server.py
python mcp-servers/web/server.py
```

Run inside **Kali WSL** or a Docker image where the underlying binaries exist.

## Regenerate from HexStrike

```bash
python scripts/harvest_hexstrike_tools.py
python scripts/count_hexstrike_tools.py   # inventory summary
```

## OpenCode / Claude Desktop

```json
{
  "mcpServers": {
    "pentest-network": {
      "command": "python",
      "args": ["D:/personal work/AI-Pentesting-Tool/mcp-servers/network/server.py"]
    },
    "pentest-web": {
      "command": "python",
      "args": ["D:/personal work/AI-Pentesting-Tool/mcp-servers/web/server.py"]
    }
  }
}
```

## Error handling (Escalation Matrix)

HexStrike's ``IntelligentErrorHandler`` (~lines 1606–2200) is lifted verbatim into [`_core/error_handler.py`](_core/error_handler.py):

- Regex error classification (timeout, permission, rate limit, tool not found, …)
- Recovery strategy selection per error type
- Retry with backoff, parameter auto-adjustment per tool, alternative tool lookup
- Human escalation payload with suggested actions
- ``GracefulDegradation`` fallback chains for partial failures

**Summary Agent integration** — before writing a failed tool result to the graph:

```python
from _core import process_tool_failure

decision = process_tool_failure(
    tool_name="nmap_scan",
    error_message=result["stderr"],
    parameters=params,
    target="10.0.0.1",
    attempt_count=1,
)
# decision["recovery_action"] → retry_with_backoff | switch_to_alternative_tool | escalate_to_human | ...
# decision["alternative_tool"], decision["adjusted_parameters"], decision["human_escalation"]
```

MCP tools pass ``use_recovery=True`` to ``run_tool()`` to apply the full loop automatically.

## Next steps (orchestrator)

1. Per-tool `parse()` → graph nodes for Summary Agent
2. FastAPI MCP client wiring by engagement phase
3. Governance gate before tool execution
