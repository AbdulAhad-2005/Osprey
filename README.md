<div align="center">

# Osprey

**An evidence-driven AI penetration-testing harness.**
Deterministic recon/vuln loop as the baseline, an optional LLM layer for judgment —
FastAPI backend, MCP gateway, interactive CLI, and a web Operator Console.

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](backend/pyproject.toml)
[![Kali image](https://img.shields.io/github/actions/workflow/status/AbdulAhad-2005/osprey/build-kali-image.yml?branch=main&label=kali%20image)](https://github.com/AbdulAhad-2005/osprey/actions/workflows/build-kali-image.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

> **Authorized use only.** Osprey runs real reconnaissance and vulnerability
> tooling. Only point it at targets you own or are explicitly authorized to
> test.

## Quick start

One command. Clones the repo (if needed), then walks you through an
interactive wizard that writes your `.env` and starts everything.

```bash
curl -fsSL https://raw.githubusercontent.com/AbdulAhad-2005/osprey/main/scripts/get.sh | bash
```

```powershell
powershell -c "irm https://raw.githubusercontent.com/AbdulAhad-2005/osprey/main/scripts/get.ps1 | iex"
```

Already cloned the repo yourself? Run the wizard directly:

```bash
bash scripts/install.sh                                        # Linux / macOS / WSL / Kali
powershell -ExecutionPolicy Bypass -File scripts\install.ps1    # Windows
```

**Already set up — just starting/stopping the backend?**

```bash
bash scripts/serve.sh                                        # Local (no Docker): Linux/macOS/WSL/Kali
powershell -ExecutionPolicy Bypass -File scripts\serve.ps1    # Local (no Docker): Windows
docker compose up -d                                          # Docker modes — up
docker compose down                                           # Docker modes — down
```

## What you get

- `backend/` — FastAPI control plane: API, database models, the conductor that tracks recon/vuln/exploit phase readiness from evidence
- `agent_core/` — the shared ReAct agent loop, driven by both the CLI and the backend
- `cli/` — an interactive terminal operator (`osprey`)
- `gui/` — a Next.js Operator Console: live chat, attack-surface graph, findings, reports
- `platform-mcp/` — an MCP gateway so any MCP-capable AI client (Claude, ChatGPT, OpenCode, Cursor, …) can drive Osprey directly
- `mcp-servers/` — the tool adapters themselves (recon, OSINT, network, web, vuln, …)

**How tools actually run.** The backend never runs scanners itself — it
`docker exec`s them into a tools container, or, when no such container is
configured, runs them natively on the host. So you can run the full
pre-built Kali image, point it at your own tools container, or skip Docker
entirely and use whatever's on your PATH.

## Setup — pick one path

All three write the same `.env` (copy `.env.example` → `.env` and set
`LLM_MODEL` + `LLM_API_KEY` — any LiteLLM provider: OpenAI, Anthropic, Gemini,
Groq, DeepSeek, Ollama, …). The wizard above does this for you; the sections
below are what to do by hand, and what each path actually runs.

| | Docker needed | Tools | Best for |
|---|---|---|---|
| **1. Full Docker** | yes | 90+ tools, pre-built Kali image | "just make it work" — zero local tool install |
| **2. Lean Docker** | yes | your own tools container | you already run a tools/Kali container |
| **3. Fully Local** | no | whatever's on your PATH | no Docker, or you want host tools directly |

<details>
<summary><b>1. Full Docker</b> — Postgres + a 90+ tool Kali container + backend, all in Docker</summary>

```bash
docker compose --profile kali up -d
```

Pulls the prebuilt `ospreytools/osprey-kali` image from Docker Hub (a few GB,
much faster than building). Postgres is on host port `5433`, backend on `9000`
— no WSL/VirtualBox needed on Windows, tools run inside the container reached
over the Docker socket.

Want to build the image yourself instead (modified `kali-tools/Dockerfile`,
need a platform the prebuilt image doesn't cover, or don't trust a third-party
image)? ~40–60 min, ~16GB disk:

```bash
docker compose --profile kali -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

Pin or redirect the image with `OSPREY_KALI_IMAGE` in `.env` — see
[`.env.example`](.env.example). It's rebuilt and republished automatically on
every change to `kali-tools/` ([workflow](.github/workflows/build-kali-image.yml)).

</details>

<details>
<summary><b>2. Lean Docker</b> — your own tools container, Postgres + backend in Docker</summary>

```bash
docker compose up --build           # note: no --profile kali
```

```
# in .env — the name of your already-running tools container:
KALI_CONTAINER=<your-tools-container-name>
```

The backend `docker exec`s each tool into that container (mounts the Docker
socket for this), so it must be running on the same Docker daemon.

> **This path needs a tools *container*, not host tools.** The backend itself
> runs inside a container here, so it can only reach another container it can
> `docker exec` into — it cannot run binaries installed on your host, and
> there's no automatic fallback. If `KALI_CONTAINER` is unset or not running,
> every compiled scanner returns "not available" (with the fix spelled out).
> **For host tools, use path 3.** `/tools` and `/health` always show your real
> execution mode and what's runnable.

</details>

<details>
<summary><b>3. Fully Local</b> — no Docker, no Postgres, tools on your own PATH</summary>

SQLite instead of Postgres — one less thing to connect to, one less thing to
misconfigure.

```bash
bash scripts/setup.sh                                        # Linux / macOS / WSL / Kali
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1    # Windows
```

Creates `.venv`, installs `agent_core` + `backend[dev]` + `cli`, and the
keyless native tool-wrapper deps. In `.env`:

```
DATABASE_URL=sqlite:///./pentest.db
KALI_CONTAINER=
```

Then start the backend with `scripts/serve.*` — see the one-liner right after
Quick start, above.

Compiled scanners (nmap, subfinder, httpx, nuclei, …) must be on your PATH;
keyless custom Python tools (domain_hunter, js_recon, subdomain_takeover, …)
work from `mcp-servers/requirements.txt` alone. **`/tools` shows exactly
what's present** — the agent plans around whatever tools it actually has.

</details>

## Troubleshooting first-time setup

The wizard catches most of this automatically — these are for a manual setup,
or if something still looks off after running it.

<details>
<summary><b>Backend won't come up / <code>503</code> after a Docker install</b></summary>

Almost always a Postgres password or host/port mismatch in `.env` — usually
from editing `DATABASE_URL` by hand, or re-running setup after switching
modes. Let the wizard rewrite it (it always writes a consistent pair):

```bash
bash scripts/install.sh    # pick option 1 or 2 again
```

If that still fails, the Postgres **volume** may have been initialized with an
old password that env vars can no longer change — reset it (this deletes
local DB data):

```bash
docker compose down -v && bash scripts/install.sh
```

Logs: `docker compose logs -f backend`.

</details>

<details>
<summary><b><code>scripts/setup.sh</code> fails creating the virtual environment</b></summary>

On Debian/Ubuntu/Kali, `python3` often ships **without** the `venv` module
split into its own package — this is the #1 cause. The script now detects
this and tries to fix it automatically; if that still fails, install it
yourself and re-run:

```bash
sudo apt-get install -y python3-venv      # Debian / Ubuntu / Kali
sudo dnf install -y python3-virtualenv    # Fedora / RHEL
sudo pacman -S python-virtualenv          # Arch / Manjaro
```

</details>

<details>
<summary><b>MCP server fails to start in Cursor/Claude/OpenCode (<code>ModuleNotFoundError: httpx</code>)</b></summary>

The MCP bridge is a separate small Python process (`platform-mcp/server.py`)
with its own deps (`mcp`, `httpx`) — if it's pointed at a system Python that
never had those installed (common after a **Docker-only** setup, which never
creates a `.venv`), the harness shows it as failed even though the backend is
healthy. The wizard now provisions a `.venv` for this automatically; if you
configured MCP manually, point the harness's `command` at
`.venv/bin/python` (or `.venv\Scripts\python.exe` on Windows) after running:

```bash
pip install -r platform-mcp/requirements.txt
```

</details>

## Optional API keys

Most tools are keyless. A few tap external intel services — set their keys in
`.env` ([`.env.example`](.env.example)) to unlock them; leave blank to skip.

| Tool(s) | Env var | Get a key |
| ------- | ------- | --------- |
| `shodan_search`, `shodan_host_info` | `SHODAN_API_KEY` | https://account.shodan.io |
| `intelx_scan` — email/subdomain harvest | `INTELX_API_KEY` | https://intelx.io/account?tab=developer |
| `intelx_scan` — leaked credentials (Identity API) | `INTELX_IDENTITY_API_KEY` | IntelX Identity Portal licence |
| `resecurity_scan` — leaked credentials | `RESECURITY_API_KEY` (+ optional `RESECURITY_API_BASE`) | https://resecurity.com |

## Run the Osprey CLI

```bash
osprey                          # interactive, from any working directory
osprey scan example.com         # scriptable scan entry point
osprey run --target example.com "show me the current attack surface"
osprey serve                    # start the backend (local setups — see above)
```

Connects to `http://localhost:9000` by default (`API_BASE_URL` to override).
It runs its own local agent loop — the same tool surface an MCP harness
drives, with your own key — independent of any backend-side agent config.
`python -m cli` and the legacy `pentest` console script also work.

> **Engine mode (`/scan <target> --engine`)** runs scanners with no LLM, so the
> tools container (or host tools) must actually be up.

<details>
<summary>CLI command reference</summary>

| Command | Description |
| ------- | ------------ |
| `/help` | Show available commands |
| `/health` | Check backend service health |
| `/tools [--all]` | Missing tools + install hints, or every tool with `--all` |
| `/models` · `/model` | List configured models · show active model + key status |
| `/scan <target> [phase]` | Bind engagement + scan (`recon`/`network`/`full`) |
| `/engage list` · `new <target>` · `set <id>` | List · create · bind to an engagement |
| `/findings` | Findings for the active engagement |
| `/tool [id]` · `/output [id]` | Recent tool calls, or expand one transcript |
| `/chat [count]` | This session's model conversation |
| `/details [mode]` | Live output detail: `compact`/`preview`/`verbose` |
| `/status` | Backend / model / active engagement status |
| `/config` · `/config reload` · `/reconnect` | Show config · reload `.env` · reconnect |
| `/reset` · `/clear` · `/exit` | Clear conversation · clear screen · exit |

Natural-language prompts work directly too — a scan follows the same visible
sense → decide → execute → evaluate → replan lifecycle with or without a
model; a configured LLM reorders/analyzes but never invents capabilities the
deterministic driver doesn't have.

</details>

### Seeing which tools you have

Tool availability is environment-aware (probed in whatever mode is active):
`/tools` in the CLI, `platform_tools` over MCP, or `GET /api/v1/tools/catalog`.
A partial toolset still works — the agent just uses fewer techniques where a
tool is missing.

## Run the Operator Console (GUI)

A Next.js web dashboard: live streaming chat with an interactive exploitation
gate, an attack-surface graph, a findings table, and a standards-aligned
report with Markdown/PDF export.

```bash
cd gui && npm install && npm run dev      # http://localhost:3100
```

The main installer asks whether to install these dependencies. For manual
setup, `scripts/setup.sh --gui` / `scripts/setup.ps1 -Gui` installs them too.

- Set your model from **Settings** (⚙ in the sidebar) — no `.env` editing.
- No prompt required — bind a target, click **Start autonomous recon**.
- **Demo mode** replays a scripted run with no backend/key needed.

Production build: `npm run build && npm start`. More detail in
[`gui/README.md`](gui/README.md).

## MCP client configuration

Point any MCP-capable AI client at `platform-mcp/server.py`. If you ran the
setup wizard, it already wrote a ready-to-paste `mcp-config.json` and offered
to configure detected clients automatically.

<details>
<summary><b>OpenCode</b></summary>

Edit `~/.config/opencode/opencode.json` (global — works in any project):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "osprey": {
      "type": "local",
      "command": ["/path/to/osprey/.venv/bin/python", "/path/to/osprey/platform-mcp/server.py"],
      "env": { "PENTEST_API_BASE": "http://localhost:9000", "PENTEST_QUICK_TIMEOUT": "30", "PENTEST_HTTP_TIMEOUT": "900" },
      "enabled": true,
      "timeout": 600000
    }
  }
}
```

Use the venv's python (not a bare `python`) so the MCP deps are guaranteed
present. Verify with `/tools` in the chat.

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Settings → Developer → Edit Config → `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osprey": {
      "command": "/path/to/osprey/.venv/bin/python",
      "args": ["/path/to/osprey/platform-mcp/server.py"],
      "cwd": "/path/to/osprey",
      "env": { "PENTEST_API_BASE": "http://localhost:9000", "PENTEST_QUICK_TIMEOUT": "30", "PENTEST_HTTP_TIMEOUT": "900" }
    }
  }
}
```

`osprey` should show as a running MCP server in Claude's settings.

</details>

<details>
<summary><b>ChatGPT Desktop</b></summary>

Settings → Plugins → MCPs → Add Server (**Name**: `osprey`, **Type**: STDIO):

| Field | Value |
|---|---|
| Command | `C:\path\to\osprey\.venv\Scripts\python.exe` (or `.venv/bin/python` on Unix) |
| Arguments | `C:\path\to\osprey\platform-mcp\server.py` |
| Working directory | `C:\path\to\osprey` |
| Env: `PENTEST_API_BASE` | `http://localhost:9000` |
| Env: `PENTEST_QUICK_TIMEOUT` | `30` |
| Env: `PENTEST_HTTP_TIMEOUT` | `900` |

Or edit `config.toml` directly:

```toml
[mcp_servers.osprey]
command = "C:\\path\\to\\osprey\\.venv\\Scripts\\python.exe"
args = ["C:\\path\\to\\osprey\\platform-mcp\\server.py"]
cwd = "C:\\path\\to\\osprey"

[mcp_servers.osprey.env]
PENTEST_API_BASE = "http://localhost:9000"
PENTEST_QUICK_TIMEOUT = "30"
PENTEST_HTTP_TIMEOUT = "900"
```

Restart ChatGPT Desktop after editing.

</details>

## Adding your own skills (drop-in, zero code)

Skills are markdown files under `skills/<phase>/` that steer the agent's
methodology for a phase. Both executors index them by YAML frontmatter
`description` and surface it for the active phase every turn, pulling full
text on demand — a well-described skill can't be missed, and more skills never
bloat the prompt.

```markdown
---
name: my-graphql-idor-playbook
description: How I hunt IDOR in GraphQL mutations on this org's APIs — the checks and payloads that work here.
phase: web
tags: [web, graphql, idor]
---
# My GraphQL IDOR playbook
...your methodology...
```

- **`phase`** — `recon`, `network`, `web`, `vuln`, `exploit`, `osint`,
  `commander`, or `shared` (always relevant). The `phase:` field is
  authoritative, independent of which folder the file lives in.
- **`description`** is what the LLM reads to decide whether to open the skill
  — make it concrete. No restart needed; `skills/` is re-read each request.

The agent can also capture a technique it discovers at runtime
(`platform_propose_skill`, approved with `/skill approve <id>`), or you can
add one in one step with `/skill add <file.md>` — these land in a git-ignored
`skills/learned/`, indexed like any other skill.

Verify indexing: `GET /api/v1/capabilities/skills-index?phase=web` (or
`platform_skills(phase="web")` over MCP).

## Backend API & entry points

- `GET /health`, `GET /api/v1/health/` — service health
- `POST /api/v1/agent/chat` — send a prompt to the agent
- `GET /api/v1/tools`, `GET /api/v1/models` — available tools / configured models
- `GET /api/v1/engagements`, `POST /api/v1/engagements` — list / create engagements
- `GET /api/v1/findings` — list findings

`backend/src/osprey/main.py` (FastAPI app) · `core/config.py` (settings) ·
`api/v1/router.py` (route registration) · `backend/tests/`.

```bash
cd backend && python -m pytest tests/ -v    # run the backend test suite
```

## Documentation

Full docs in [`docs/`](docs/README.md):

- [Architecture & workflow](docs/ARCHITECTURE.md) — how it works and why
- [Operator guide](docs/PLATFORM_GUIDE.md) — running and driving the platform
- [Developer guide](docs/DEVELOPER_GUIDE.md) — code map and pipeline trace
- [Capability reference](docs/CAPABILITY_REFERENCE.md) — per-tool + memory model
- [Integration contract](docs/INTEGRATION_CONTRACT.md) — MCP + HTTP APIs
- [Status & roadmap](docs/STATUS_AND_ROADMAP.md) — what's built vs. planned

## Contributing

Issues, feature suggestions, and PRs are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[GNU AGPL v3.0](LICENSE).
