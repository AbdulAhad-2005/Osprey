# Nmap Wrapper (`network` capability domain)

A single-file, dependency-free Python wrapper around the `nmap` binary, built to
be exposed to an LLM (the network-phase agent) as a clean set of callable tools.

- **File:** `nmap_wrapper.py`
- **Plane:** Execution Plane → `network.mcp` (port, service, and TLS enumeration)
- **Dependencies:** none beyond the Python standard library + the `nmap` binary on the host
- **Output:** every call returns a normalised, JSON-serialisable `dict` ready to
  summarise, store in the engagement graph, or feed back to the planner

---

## 1. Why this exists

The architecture separates the **reasoning plane** (LLM planner/critic) from the
**execution plane** (tools). The planner should never care whether the underlying
tool is Nmap, Rustscan, or Masscan — it only emits structured tool calls and gets
back structured results.

This wrapper is the Nmap adapter for that contract. It gives the LLM:

1. **Defined functions** for every common scan and evasion technique (so the
   model doesn't have to memorise nmap syntax).
2. **A custom escape hatch** (`custom_scan`) so the model can still compose *any*
   nmap command when it needs to bypass a firewall/IDS or do something unusual —
   this directly serves the "escalation matrix / don't stall when blocked" goal
   in the architecture.
3. **Structured, parsed output** so findings (hosts, ports, services, versions,
   CPEs, OS guesses, NSE script results) drop straight into the memory/graph
   plane without extra parsing.

---

## 2. End-to-end flow

```
                       LLM / Network agent
                              │  (chooses a tool + arguments)
                              ▼
      ┌───────────────────────────────────────────────┐
      │  NmapScanner method  (e.g. syn_scan, udp_scan) │
      │  or custom_scan(flags=...)  ← escape hatch      │
      └───────────────────────┬───────────────────────┘
                              ▼
      ┌───────────────────────────────────────────────┐
      │  _run()  – assemble argument vector             │
      │   scan flags + ports + EvasionOptions + extra   │
      │   + "--"  + target                              │
      └───────────────────────┬───────────────────────┘
                              ▼
      ┌───────────────────────────────────────────────┐
      │  _execute()  – subprocess.run (shell=False)     │
      │   injects "-oN -" (human report → stdout) AND   │
      │   "-oX <tmp>" (full XML → file); enforce timeout│
      └───────────────────────┬───────────────────────┘
                              ▼
      ┌───────────────────────────────────────────────┐
      │  _parse_nmap_xml()  – XML → hosts + summary     │
      └───────────────────────┬───────────────────────┘
                              ▼
      ┌───────────────────────────────────────────────┐
      │  ScanResult.to_dict()  – normalised JSON dict   │
      │   THREE views of the run, none a subset:         │
      │   • raw_output  (full human report)              │
      │   • raw_xml     (full XML, evidence)             │
      │   • hosts/summary (structured extraction)        │
      └───────────────────────┬───────────────────────┘
                              ▼
             back to LLM  →  summary agent  →  engagement graph
```

**In words:**

1. The agent calls a method with a target and optional knobs.
2. `_run()` builds the command from parts: the scan flag(s), `-p <ports>`, any
   `EvasionOptions`, any `extra_args`, and a `--` separator before the target.
3. `_execute()` injects the wrapper-controlled output (**`-oN -`** so the full
   human-readable report lands on stdout, **`-oX <tempfile>`** so the full XML is
   written for parsing/evidence), runs it via `subprocess.run` with
   `shell=False` and a timeout, then cleans up the temp file.
4. `_parse_nmap_xml()` turns the XML into structured hosts + a run summary.
5. The result is returned as a single normalised dict carrying **all three
   views** — so the summary agent can see literally everything nmap produced,
   the same way a human pentester reads the whole report (this completeness is
   the whole point; see §5).

---

## 3. What comes back (result schema)

> **Completeness guarantee.** The summary agent must be able to see *everything*
> nmap returned — not just the fields the parser models. That total visibility is
> the edge over a human pentester (who reads the whole report and notices the odd
> line the checklist misses). So every result carries **three independent views**
> of the same run, and none is a subset of another:
>
> - `raw_output` — the full human-readable ("normal") report, exactly what a
>   pentester sees on screen. Loss-free primary view.
> - `raw_xml` — the complete XML, for evidence bundling and re-parsing.
> - `hosts` / `summary` — the structured extraction for the graph/planner.
>
> `raw_stderr` additionally carries nmap's warnings/errors. Nothing is dropped.

Every public method returns the same shape:

```jsonc
{
  "command": "nmap -sS -p 80,443 -oN - -oX <tmp> -- scanme.nmap.org",
  "success": true,             // returncode 0 AND XML parsed AND run not aborted
  "returncode": 0,
  "duration_seconds": 1.53,
  "summary": {
    "args": "nmap -sS ...", "version": "7.94", "start": "Wed Jul 8 ...",
    "hosts_up": 1, "hosts_down": 0, "hosts_total": 1,
    "elapsed": "1.5", "summary": "Nmap done ...",
    "run_exit": "success",             // "error" if the scan aborted early
    "run_errormsg": null,              // populated when nmap reports an abort
    "open_ports": 1,
    "port_state_counts": {"open": 1, "closed": 994, "filtered": 4}, // incl. extraports
    "pre_scripts": [], "post_scripts": []   // scan-level NSE (targets-asn, etc.)
  },
  "hosts": [
    {
      "state": "up", "reason": "syn-ack",
      "addresses": [{"addr": "45.33.32.156", "type": "ipv4", "vendor": null}],
      "hostnames": [{"name": "scanme.nmap.org", "type": "user"}],
      "ports": [
        {
          "port": 80, "protocol": "tcp", "state": "open", "reason": "syn-ack",
          "service": "http", "product": "Apache httpd", "version": "2.4.7",
          "extrainfo": null, "tunnel": null, "method": "probed", "conf": "10",
          "cpe": ["cpe:/a:apache:http_server:2.4.7"],
          "scripts": [
            {"id": "http-title", "output": "Go ahead and ScanMe!"},
            {"id": "vulners", "output": "...", "data": {"...": [{"id": "CVE-...", "cvss": "6.8"}]}}
          ]
        }
      ],
      "extraports": [{"state": "closed", "count": 994, "reasons": [{"reason": "resets", "count": 994}]}],
      "os": [{"name": "Linux 3.13", "accuracy": 96, "classes": [{"family": "Linux", "gen": "3.X"}]}],
      "uptime": {"seconds": 211324, "lastboot": "..."},
      "distance": 11,
      "traceroute": {"port": 80, "protocol": "tcp", "hops": [{"ttl": 1, "ipaddr": "192.168.1.1", "rtt": "1.20"}]}
    }
  ],
  "raw_output": "Starting Nmap 7.94 ...\nPORT   STATE SERVICE\n80/tcp open  http ...",  // human report
  "raw_xml": "<nmaprun>...</nmaprun>",   // full XML for evidence bundling
  "raw_stdout": "…",                       // back-compat alias of raw_output
  "raw_stderr": "",                        // warnings / errors
  "error": null                            // populated on any failure
}
```

This maps cleanly onto the engagement-graph entities (assets, IPs, ports,
technologies) and the report finding schema (evidence: command + raw output).
The structured `data` inside NSE scripts (e.g. `vulners` CVE/CVSS tables) feeds
straight into CVE correlation later in the pipeline.

---

## 4. The API surface

### 4.1 Constructing the scanner

```python
from nmap_wrapper import NmapScanner, EvasionOptions

scanner = NmapScanner(
    nmap_path="nmap",       # path or name of the nmap binary
    default_timeout=600,    # seconds before a scan is killed
    sudo=False,             # prefix sudo on POSIX (needed for raw-socket scans)
)
```

If the binary can't be found, the constructor raises `NmapError` immediately —
so a misconfigured host fails loudly instead of at scan time.

### 4.2 Defined scan methods

| Method | Nmap | Purpose |
|---|---|---|
| `ping_scan` | `-sn` | Host discovery only ("is it alive?") |
| `list_scan` | `-sL` | Enumerate targets, send no packets |
| `no_ping_scan` | `-Pn` | Skip discovery, treat host as up (ICMP blocked) |
| `syn_scan` | `-sS` | Fast half-open scan (default; needs privilege) |
| `connect_scan` | `-sT` | Full handshake, works unprivileged |
| `udp_scan` | `-sU` | UDP services (DNS, SNMP, DHCP…) |
| `null_scan` | `-sN` | No flags — stealthy, Unix-only |
| `fin_scan` | `-sF` | Lone FIN — stealthy firewall bypass |
| `xmas_scan` | `-sX` | FIN+PSH+URG — stealthy firewall bypass |
| `ack_scan` | `-sA` | Map firewall rules (stateful vs stateless) |
| `idle_scan` | `-sI <zombie>` | Anonymous scan bounced off a zombie host |
| `ftp_bounce_scan` | `-b <relay>` | Anonymous scan via legacy FTP relay |
| `version_scan` | `-sV` | Service/version fingerprinting (+ intensity) |
| `os_scan` | `-O` | OS fingerprinting (+ guess/limit) |
| `aggressive_scan` | `-A` | OS + version + scripts + traceroute |
| `script_scan` | `--script` | Run NSE scripts/categories |
| `quick_scan` | `--top-ports N` | Fast common-port sweep |
| `full_port_scan` | `-p- -sS` | All 65535 TCP ports |
| `comprehensive_scan` | `-sS -sV -O -sC` | One-shot maximum-signal recon |

Every scan method accepts (where relevant): `target`, `ports`, `evasion`,
`extra_args`, `timeout`, and `privileged`.

### 4.3 Evasion / firewall-bypass knobs

`EvasionOptions` layers stealth onto *any* defined scan (no need to drop to a
custom command):

```python
ev = EvasionOptions(
    timing="sneaky",     # 0-5 or paranoid/sneaky/polite/normal/aggressive/insane → -T<n>
    fragment=True,        # -f
    mtu=32,               # --mtu 32 (multiple of 8)
    source_port=53,       # -g 53 (masquerade as DNS)
    decoys="RND:10",      # -D RND:10 (or a list of IPs)
    spoof_mac="0",        # --spoof-mac
    bad_checksum=True,    # --badsum
    data_length=64,       # --data-length 64
    no_dns=True,          # -n (faster, quieter)
)
scanner.syn_scan("10.0.0.5", ports="1-1000", evasion=ev)
```

### 4.4 The custom escape hatch (LLM-driven)

When the defined helpers don't fit, the model composes the exact command:

```python
scanner.custom_scan("10.0.0.5", flags="-sS -p 80,443 -T2 -f -g 53 --data-length 24")
# or as a token list:
scanner.custom_scan("10.0.0.5", flags=["-sS", "-p", "80", "-T2"])
```

`raw_command()` is the lowest level if even the target/output handling gets in
the way.

---

## 5. Logics introduced (design decisions)

These are the deliberate behaviours baked into the wrapper — worth knowing when
you extend it:

1. **Total-visibility output (the headline logic).** Every run captures the full
   human-readable report on stdout (`-oN -`) **and** the full XML to a temp file
   (`-oX <tmp>`), then parses the XML. The result exposes all three — `raw_output`,
   `raw_xml`, and the structured `hosts`/`summary` — so the summary agent sees
   *exactly* what a human pentester would, plus a machine-readable form. Nothing
   nmap prints is ever discarded. Any user-supplied output flag is stripped
   (`_strip_output_flags()`) so the wrapper stays the single source of output.

2. **Comprehensive parsing (no silent under-extraction).** Beyond host/port/
   service/OS, the parser now also captures: `extraports` (the "998 closed ports"
   aggregate) folded into `summary.port_state_counts`; OS `classes`; `uptime`,
   `distance`, and `traceroute`; structured NSE data (`<table>`/`<elem>` → nested
   dict, e.g. `vulners` CVE/CVSS tables) alongside the flat script `output`;
   scan-level `pre_scripts`/`post_scripts`; and the run's `run_exit`/`run_errormsg`.
   Anything still unmodeled remains recoverable from `raw_output`/`raw_xml`.

3. **Shell-free execution.** Commands run with `subprocess.run(shell=False)` and
   an argument **list**, so shell metacharacters in flags/targets are never
   interpreted → no command injection.

4. **Flag-smuggling protection.** The target is validated (`_validate_target()`
   rejects tokens starting with `-`) and passed **after a `--` separator**, so a
   hostile or malformed target can never be parsed as an nmap option.

5. **Honest success flag.** `success` is `True` only when the process exit code is
   0, the XML parsed cleanly, **and** the run did not abort early
   (`run_exit != "error"` and no `run_errormsg`) — so an nmap that exits 0 but
   was interrupted is still reported as a failure the planner can react to.

6. **Robust failure handling.** Timeouts (`TimeoutExpired`), missing binary, and
   subprocess/OS errors are all caught and returned as a normal result dict with
   `success=false`. On timeout, any **partial** XML already written is still
   parsed and returned (`summary.partial = true`) — no data lost even on abort.

7. **Timing templates by name.** `EvasionOptions.timing` accepts `0-5` or the
   human names (`paranoid`…`insane`) so LLM-generated calls read naturally.

8. **Privilege awareness.** Raw-socket scans (`-sS`, `-sU`, `-sN/-sF/-sX`, `-O`,
   idle) are marked `privileged=True`; on POSIX a `sudo=True` scanner prefixes
   `sudo`. On Windows the host process must be elevated with Npcap installed.

9. **Sensible defaults.** `aggressive_scan`/`quick_scan` default to `-T4` timing
   unless the caller overrides `evasion`, matching common real-world usage.

---

## 6. Connecting it to an LLM

There are two ways to expose this to a model. Both work because the wrapper
already returns clean, JSON-serialisable dicts.

### Option A — direct tool/function-calling (simplest)

Wrap each method as a tool the model can call. Example sketch:

```python
from nmap_wrapper import NmapScanner, EvasionOptions

scanner = NmapScanner(sudo=True)

TOOLS = {
    "nmap_ping_scan":   lambda target: scanner.ping_scan(target),
    "nmap_syn_scan":    lambda target, ports=None: scanner.syn_scan(target, ports=ports),
    "nmap_version_scan":lambda target, ports=None: scanner.version_scan(target, ports=ports),
    "nmap_custom_scan": lambda target, flags: scanner.custom_scan(target, flags),
}

def dispatch(name, **kwargs):
    return TOOLS[name](**kwargs)   # returns a JSON-serialisable dict
```

Give the model the method names, docstrings, and parameters as its tool schema
(the docstrings in `nmap_wrapper.py` are written to double as tool descriptions).

### Option B — as an MCP server (recommended; matches the architecture)

This folder ships a ready MCP server, `server.py`, that imports `NmapScanner`
and exposes each scan as an MCP tool. The wrapper stays framework-agnostic — only
`server.py` depends on the MCP SDK. Any MCP-capable client (Claude Desktop,
OpenCode, Cursor, the platform planner) can drive it.

Files involved:

| File | Role |
|---|---|
| `nmap_wrapper.py` | The tool logic (stdlib-only). |
| `server.py` | MCP layer — wraps each `NmapScanner` method as an `@mcp.tool()`. |
| `requirements.txt` | Just `mcp` (the SDK), needed only by `server.py`. |
| `Dockerfile` | Packages wrapper + server **and installs nmap** so scans run. |
| `.dockerignore` | Keeps the image slim. |

Tools exposed by `server.py`: `nmap_version`, `nmap_ping_scan`,
`nmap_no_ping_scan`, `nmap_syn_scan`, `nmap_connect_scan`, `nmap_udp_scan`,
`nmap_version_scan`, `nmap_os_scan`, `nmap_aggressive_scan`, `nmap_script_scan`,
`nmap_quick_scan`, `nmap_full_port_scan`, `nmap_comprehensive_scan`,
`nmap_stealth_scan` (syn/connect/null/fin/xmas/ack + all evasion knobs),
`nmap_idle_scan`, and `nmap_custom_scan` (arbitrary flags). Each returns the
same complete result described in §3.

Every tool docstring is written to double as the tool's description, and the
type hints generate the input schema automatically (FastMCP).

#### Run it locally (no Docker)

```bash
pip install -r requirements.txt   # installs the mcp SDK; nmap must be on PATH
python server.py                  # serves over stdio (default MCP transport)
```

Configuration via env vars: `NMAP_PATH` (default `nmap`), `NMAP_TIMEOUT`
(seconds, default `600`), `NMAP_SUDO` (`true`/`false`, prefixes sudo on POSIX).

---

## 6b. Packaging in Docker (installs nmap inside)

The `Dockerfile` builds a self-contained image: Python + the MCP server + **nmap
installed**, so the container can actually run scans.

```bash
# from the repo root
docker build -t pentest-network-mcp mcp-servers/network

# smoke test (should print the nmap version JSON handshake is via stdio):
docker run -i --rm --cap-add=NET_RAW --cap-add=NET_ADMIN pentest-network-mcp
```

Notes:

- **`-i` is mandatory** — MCP talks to the container over stdio; without it the
  container appears unresponsive.
- **`--rm`** — clients spawn a fresh container per connection; this stops stopped
  containers from piling up.
- **`--cap-add=NET_RAW`** (default in Docker) enables raw-socket scans (`-sS`,
  `-sU`, `-O`, idle). Add **`--cap-add=NET_ADMIN`** for a few advanced options.
  For a hardened setup, drop these and use `nmap_connect_scan` (`-sT`) instead.
- The container runs as root so raw sockets work; `NMAP_SUDO` stays `false`.

### Connect the Docker server to Claude Desktop

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config):
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```jsonc
{
  "mcpServers": {
    "network-nmap": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
        "pentest-network-mcp"
      ]
    }
  }
}
```

Then fully quit and relaunch Claude Desktop. The `nmap_*` tools appear in the
tools list.

### Connect the Docker server to OpenCode

Add to `opencode.json` (project root) or `~/.config/opencode/opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "network-nmap": {
      "type": "local",
      "command": [
        "docker", "run", "-i", "--rm",
        "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
        "pentest-network-mcp"
      ],
      "enabled": true,
      "timeout": 60000
    }
  }
}
```

(Run OpenCode from the folder containing `opencode.json`, or use the global path.
The image build can also be pushed to a registry and referenced by its full name,
e.g. `ghcr.io/you/pentest-network-mcp:latest`.)

### Run without Docker (either client)

Point the client at the local script instead of Docker:

```jsonc
// Claude Desktop
{ "mcpServers": { "network-nmap": {
  "command": "python",
  "args": ["D:/personal work/AI-Pentesting-Tool/mcp-servers/network/server.py"]
}}}

// OpenCode
{ "mcp": { "network-nmap": {
  "type": "local",
  "command": ["python", "mcp-servers/network/server.py"],
  "enabled": true
}}}
```

Because the client only ever emits structured MCP tool calls, swapping Nmap for
another scanner later means rewriting this adapter only — the planner/client is
untouched. That's the LLM-agnostic / tool-agnostic contract the architecture
requires.

> Note: `mcp` (the SDK) is a dependency of `server.py` only, never of
> `nmap_wrapper.py`. Keep it that way so the wrapper stays importable anywhere.

---

## 7. Quick start / smoke test

```bash
# prints nmap version, then runs a quick scan if a target is given
python nmap_wrapper.py                 # version banner only
python nmap_wrapper.py scanme.nmap.org # version + quick_scan on the target
```

```python
from nmap_wrapper import NmapScanner

scanner = NmapScanner()
print(scanner.version())                       # confirm nmap is reachable
result = scanner.quick_scan("scanme.nmap.org") # returns the normalised dict
for host in result["hosts"]:
    for port in host["ports"]:
        print(host["addresses"], port["port"], port["state"], port["service"])
```

---

## 8. Requirements & caveats

- **Nmap must be installed** and on `PATH` (or pass `nmap_path=`). Windows also
  needs **Npcap** for raw-socket scans.
- **Privileges:** SYN/UDP/NULL/FIN/XMAS/OS/idle scans need root/admin.
- **Authorization:** this only wraps nmap — scope enforcement, rate limiting, and
  approval gates live in the **Governance Plane**. Do not scan targets you are
  not explicitly authorized to test.
- **Timeouts:** long scans (full port range, UDP) may exceed `default_timeout`;
  raise it per call via `timeout=`.
