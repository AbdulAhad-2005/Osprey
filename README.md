# Autonomous Pentesting Tool

An autonomous AI penetration testing platform with a FastAPI backend and a Python CLI operator interface.

## Architecture

- `backend/` — FastAPI control plane, API endpoints, database models, workflow logic
- `cli/` — Python CLI tool (prompt_toolkit) for interacting with the platform
- `mcp-servers/` — Capability-based tool adapters for recon, osint, network, web, vuln, …
- `platform-mcp/` — MCP gateway server connecting AI clients to the platform
- `docker-compose.yml` — Postgres + (optional) Kali Linux tools + FastAPI backend

**How tools run.** The backend never runs scanners itself — it `docker exec`s them
into a tools container (`KALI_CONTAINER`), or, when no such container is running,
executes them **natively on the host**. So you can run the full Kali image, bring
your own tools, or run entirely without Docker.

## Setup — pick the path that fits you

All three paths start the same way:

```bash
cp .env.example .env
# Edit .env: set LLM_MODEL + LLM_API_KEY (any LiteLLM provider — OpenAI, Anthropic,
# Gemini, Groq, DeepSeek, Ollama, …). See the comments in the file.
```

### Path A — Full Docker stack (easiest; no local tools needed)

Builds Postgres, a Kali container with 90+ tools, and the backend. The heavy Kali
image is behind the `kali` compose profile, so you opt into the long build explicitly:

```bash
docker compose --profile kali up --build
```

> No WSL / VirtualBox needed on Windows — the tools run inside the container,
> reached over the Docker socket. Postgres is on host port 5433, backend on 9000.

### Path B — Lean Docker + bring your own tools (skip the Kali build)

Already have the tools (native Kali, or your own container) and don't want to build
the image? Start just Postgres + backend:

```bash
docker compose up --build           # note: no --profile kali
```

Then in `.env` either:
- point `KALI_CONTAINER=<your-container-name>` at a running tools container, or
- set `KALI_CONTAINER=` (empty) to run tools directly on the host.

If the named container isn't running, the backend falls back to native execution
automatically.

### Path C — Fully local, no Docker

Virtualenv at the repo root, SQLite instead of Postgres, tools on your host PATH:

```bash
# creates .venv, installs backend[dev] + cli + native tool deps
bash scripts/setup.sh                       # Linux / macOS / WSL / Kali
# or on Windows:
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

In `.env` set a keyless DB and native execution:

```
DATABASE_URL=sqlite:///./pentest.db
KALI_CONTAINER=
```

Then run the backend (the SQLite schema is created on startup):

```bash
uvicorn pentest_platform.main:app --host 0.0.0.0 --port 9000
```

Compiled scanners (nmap, subfinder, httpx, nuclei, …) must be on your PATH; the
keyless custom Python tools (domain_hunter, js_recon, subdomain_takeover, contact
harvest, …) work from `mcp-servers/requirements.txt` alone. **`/tools` shows exactly
what's present** (see below) and the agent only uses tools it actually has.

## Dependencies (pip)

`pyproject.toml` is the source of truth for each package's declared dependencies:

- `backend/pyproject.toml` — backend runtime + `[dev]` extras (pytest, ruff, httpx)
- `cli/pyproject.toml` — CLI runtime
- `mcp-servers/requirements.txt` — Python deps for native tool wrappers

The `requirements.txt` files are generated pinned locks (regenerate with
`pip-compile pyproject.toml`).

## Run the CLI

Prerequisites: the backend is up, `.env` has `ENABLE_BUILTIN_AGENT=true` (the CLI
drives the backend's built-in agent; the OpenCode/MCP path does not need this), and
`LLM_API_KEY`/`LLM_MODEL` are set.

If you used `scripts/setup.*`, the CLI is already installed. Otherwise:

```bash
pip install -e ./cli            # from the repo root (Windows + Linux)
```

Run it (connects to `http://localhost:9000`; override with `API_BASE_URL`):

```bash
python -m cli                   # or the `pentest` console script
```

> **Engine mode (`/scan <target> --engine`) needs a working tool backend.** It runs
> scanners with no LLM, so the Kali tools container must be up:
> `docker compose --profile kali up -d` (or point `KALI_CONTAINER` at your own tools
> container / set it empty for native host tools). If no backend is available the
> engine now fails fast with one clear message instead of reporting every tool as
> failed.

### CLI commands

| Command                       | Description                                       |
| ----------------------------- | ------------------------------------------------- |
| `/help`                       | Show available commands                           |
| `/health`                     | Check backend service health                      |
| `/tools`                      | List tools — **installed vs missing in your env** |
| `/models`                     | List configured LLM models                        |
| `/model`                      | Show active model + key status                    |
| `/scan <target> [phase]`      | Bind engagement + scan (`recon`/`network`/`full`) |
| `/engage list`                | List all engagements                              |
| `/engage new <target>`        | Create a fresh engagement for a target            |
| `/engage set <id>`            | Bind this session to an existing engagement       |
| `/findings`                   | Show findings for the active engagement           |
| `/status`                     | Backend / model / active engagement status        |
| `/config` · `/config reload`  | Show config · force backend to re-read `.env`     |
| `/reconnect`                  | Re-read `.env` and reconnect to `API_BASE_URL`    |
| `/reset` · `/clear` · `/exit` | Clear conversation · clear screen · exit          |

`/scan <target> [phase]` binds an engagement so `/findings` and prompts know the
target. You can also type natural-language prompts directly. During a run the CLI
streams commander decisions, live tool start/finish, and per-phase reports.

### Seeing which tools you have

Tool availability is environment-aware: the backend probes each binary in whatever
execution mode is active (Kali container or host). Surface it with:

- **CLI:** `/tools` — a table of every tool with `installed` / `missing`.
- **MCP / harness:** the `platform_tools` tool, or `GET /api/v1/tools/catalog`
  (returns per-tool `installed` plus a summary count).

The agent plans around what's present, so a partial toolset still works — you just
get fewer techniques where a tool is missing.

## MCP Client Configuration (Alternate Approach)

Connect your AI client directly to the platform via MCP. All clients use the same MCP server at `platform-mcp/server.py`.

### OpenCode (recommended)

Edit `~/.config/opencode/opencode.json` (global config — works in any project):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "pentest-platform": {
      "type": "local",
      "command": ["python", "C:\\path\\to\\AI-Pentesting-Tool\\platform-mcp\\server.py"],
      "env": {
        "PENTEST_API_BASE": "http://localhost:9000",
        "PENTEST_QUICK_TIMEOUT": "30",
        "PENTEST_HTTP_TIMEOUT": "900"
      },
      "enabled": true,
      "timeout": 600000
    }
  }
}
```

Replace `C:\\path\\to` with the absolute path to the project. The global config makes `pentest-platform` tools available in any repository you open with OpenCode. Verify with `/tools` in the chat — you should see all MCP tools listed.

### Claude Desktop (native MCP support)

In Claude Desktop app, go to Settings -> Developer -> Edit Config -> Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pentest-platform": {
      "command": "python",
      "args": [
        "C:\\path\\to\\AI-Pentesting-Tool\\platform-mcp\\server.py"
      ],
      "cwd": "C:\\path\\to\\AI-Pentesting-Tool",
      "env": {
        "PENTEST_API_BASE": "http://localhost:9000",
        "PENTEST_QUICK_TIMEOUT": "30",
        "PENTEST_HTTP_TIMEOUT": "900"
      }
    }
  }
}
```

Replace `C:\\path\\to` with your actual project path. You should see `pentest-platform` listed as a running MCP server in Claude's settings.

### ChatGPT Desktop

You can configure your MCP server either from the graphical interface or directly through `config.toml`.

#### Option 1 (Recommended): GUI Configuration

Open:

Settings → Plugins → MCPs → Add Server

Configure the server as follows.

##### Name

```
pentest-platform
```

##### Type

```
STDIO
```

##### Command

System Python:

```
python
```

or preferably your virtual environment:

```
C:\path\to\AI-Pentesting-Tool\.venv\Scripts\python.exe
```

##### Arguments

```
C:\path\to\AI-Pentesting-Tool\platform-mcp\server.py
```

##### Environment Variables

| Variable | Value |
|----------|-------|
| PENTEST_API_BASE | http://localhost:9000 |
| PENTEST_QUICK_TIMEOUT | 30 |
| PENTEST_HTTP_TIMEOUT | 900 |

##### Working Directory

```
C:\path\to\AI-Pentesting-Tool
```

Click **Save**.

If the configuration is valid, ChatGPT Desktop will automatically launch the MCP server whenever it is needed.

---

#### Option 2: config.toml

Instead of using the GUI, you can edit ChatGPT Desktop's `config.toml`.

Add:

```toml
[mcp_servers.pentest-platform]
command = "python"

args = [
    "C:\\path\\to\\AI-Pentesting-Tool\\platform-mcp\\server.py"
]

cwd = "C:\\path\\to\\AI-Pentesting-Tool"

[mcp_servers.pentest-platform.env]
PENTEST_API_BASE = "http://localhost:9000"
PENTEST_QUICK_TIMEOUT = "30"
PENTEST_HTTP_TIMEOUT = "900"
```

If using a virtual environment, replace the command with:

```toml
command = "C:\\path\\to\\AI-Pentesting-Tool\\.venv\\Scripts\\python.exe"
```

Restart ChatGPT Desktop after editing `config.toml`.

For the best integrated experience, use **OpenCode** or **Claude Desktop**.

## Backend API endpoints

- `GET /health` — Service health check
- `GET /api/v1/health/` — API health check
- `POST /api/v1/agent/chat` — Send a prompt to the agent
- `GET /api/v1/tools` — List available tools
- `GET /api/v1/models` — List configured models
- `GET /api/v1/engagements` — List engagements
- `POST /api/v1/engagements` — Create an engagement
- `GET /api/v1/findings` — List findings

## Backend entry points

- `backend/src/pentest_platform/main.py` — FastAPI app
- `backend/src/pentest_platform/core/config.py` — Runtime settings
- `backend/src/pentest_platform/api/v1/router.py` — API route registration
- `backend/tests/` — Health check tests

## Running tests

```bash
cd backend
python -m pytest tests/ -v
```

## Documentation

Full docs live in [`docs/`](docs/README.md). Quick links:

- [Architecture & workflow](docs/ARCHITECTURE.md) — how it works and why
- [Operator guide](docs/PLATFORM_GUIDE.md) — running and driving the platform
- [Developer guide](docs/DEVELOPER_GUIDE.md) — code map and pipeline trace
- [Capability reference](docs/CAPABILITY_REFERENCE.md) — per-tool + memory model
- [Integration contract](docs/INTEGRATION_CONTRACT.md) — MCP + HTTP APIs
- [Status & roadmap](docs/STATUS_AND_ROADMAP.md) — what's built vs planned

## Next steps

See [`docs/STATUS_AND_ROADMAP.md`](docs/STATUS_AND_ROADMAP.md) for the current status and the active reliability plan. Near-term focus: real scope/ROE governance, durable jobs + attempt history, graph/evidence provenance hardening, then phase expansion (web/vuln) and the killchain engine.

## Tools Analyzed

Reference-tool deep dives live in [`Comparative Analysis/`](Comparative%20Analysis/). Summary document:
https://docs.google.com/document/d/1XqAMlZ9ErRywIHvR0FinwqmysCgSqYzIGtXoqmlsDGc/edit?usp=sharing

## Contributing

Contributions are welcome! Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines on reporting issues, suggesting features, and submitting pull requests.

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [`LICENSE`](LICENSE) file for details.

