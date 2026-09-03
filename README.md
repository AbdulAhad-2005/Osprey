# Osprey

Osprey is an autonomous AI penetration testing platform with a FastAPI backend, MCP gateway, and an interactive Python CLI operator interface.

## Architecture

- `backend/` — FastAPI control plane, API endpoints, database models, workflow logic
- `cli/` — Osprey CLI tool (prompt_toolkit + Rich) for interacting with the platform
- `mcp-servers/` — Capability-based tool adapters for recon, osint, network, web, vuln, …
- `platform-mcp/` — MCP gateway server connecting AI clients to the platform
- `docker-compose.yml` — Postgres + (optional) Kali Linux tools + FastAPI backend

**How tools run.** The backend never runs scanners itself — it `docker exec`s them
into a tools container (`KALI_CONTAINER`), or, when no such container is running,
executes them **natively on the host**. So you can run the full Kali image, bring
your own tools, or run entirely without Docker.

## Setup — pick the path that fits you

Quick guide:
- **Want it to just work, don't mind a one-time heavy build?** → **Path A** (full Docker + Kali, all tools included — preferable).
- **Have your own tools *container*?** → **Path B** (lean Docker, point `KALI_CONTAINER` at it).
- **Want to use tools already on your machine, or no Docker at all?** → **Path C** (fully local). This is the right choice for host tools — a containerized backend (Path B) cannot reach them.

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
> takes time to build kali image ~40-50 min and additional disk space ~16GB
> No WSL / VirtualBox needed on Windows — the tools run inside the container,
> reached over the Docker socket. Postgres is on host port 5433, backend on 9000.

### Path B — Lean Docker + your own tools container (skip the Kali build)

Already have a tools container (a native Kali image, or your own) and don't want to
build ours? Start just Postgres + backend, then point the backend at that container:

```bash
docker compose up --build           # note: no --profile kali
```

```
# in .env — the name of your already-running tools container:
KALI_CONTAINER=<your-tools-container-name>
```

The backend `docker exec`s each tool into that container (it mounts the Docker
socket for this), so the container must be running on the same Docker daemon.

> **Important — Path B needs a tools *container*, not host tools.** The backend
> itself runs inside a container here, so it can only reach tools in another
> container it can `docker exec` into — it **cannot** run binaries installed on your
> host machine, and there is no automatic "fall back to host tools". If
> `KALI_CONTAINER` is unset or its container isn't running, only the built-in Python
> tools work and every compiled scanner returns *"not available in your execution
> environment"* (with the fix). **To use the tools already installed on your host,
> use Path C** — a native backend, which runs them directly. `/tools` and
> `/health` show your real execution mode and what's runnable.

### Path C — Fully local, no Docker (uses your host's own tools)

The path for running Osprey against tools already on your machine, with no Docker at
all. Virtualenv at the repo root, SQLite instead of Postgres, tools on your host PATH:

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
uvicorn osprey.main:app --host 0.0.0.0 --port 9000
```

Compiled scanners (nmap, subfinder, httpx, nuclei, …) must be on your PATH; the
keyless custom Python tools (domain_hunter, js_recon, subdomain_takeover, contact
harvest, …) work from `mcp-servers/requirements.txt` alone. **`/tools` shows exactly
what's present** (see below) and the agent only uses tools it actually has.

## Optional API keys

Most tools are keyless. A few tap external intel services — set their keys in `.env`
(see [`.env.example`](.env.example)) to unlock them; leave blank to skip. Keys are
forwarded into the tools container automatically.

| Tool(s) | Env var | Get a key |
| ------- | ------- | --------- |
| `shodan_search`, `shodan_host_info` | `SHODAN_API_KEY` | https://account.shodan.io |
| `intelx_scan` — email/subdomain harvest | `INTELX_API_KEY` | https://intelx.io/account?tab=developer |
| `intelx_scan` — **leaked credentials** (Identity API) | `INTELX_IDENTITY_API_KEY` | IntelX Identity Portal licence |
| `resecurity_scan` — leaked credentials | `RESECURITY_API_KEY` (+ optional `RESECURITY_API_BASE`/`RESECURITY_ENDPOINT`) | https://resecurity.com |

## Dependencies (pip)

`pyproject.toml` is the source of truth for each package's declared dependencies:

- `backend/pyproject.toml` — backend runtime + `[dev]` extras (pytest, ruff, httpx)
- `cli/pyproject.toml` — CLI runtime
- `mcp-servers/requirements.txt` — Python deps for native tool wrappers

The `requirements.txt` files are generated pinned locks (regenerate with
`pip-compile pyproject.toml`).

## Run Osprey CLI

Prerequisites: the backend is up, `.env` has `ENABLE_BUILTIN_AGENT=true` (the CLI
drives the backend's built-in agent; the OpenCode/MCP path does not need this), and
`LLM_API_KEY`/`LLM_MODEL` are set.

If you used `scripts/setup.*`, the CLI is already installed. Otherwise:

```bash
pip install -e ./cli            # from the repo root (Windows + Linux)
```

Run it (connects to `http://localhost:9000`; override with `API_BASE_URL`):

```bash
osprey                          # interactive CLI, from any working directory
osprey scan example.com         # scriptable scan entry point
osprey run --target example.com "show me the current attack surface"
```

`python -m cli` and the legacy `pentest` console script still work.

> **Engine mode (`/scan <target> --engine`) needs a working tool backend.** It runs
> scanners with no LLM, so the Kali tools container must be up:
> `docker compose --profile kali up -d` (or point `KALI_CONTAINER` at your own tools
> container / set it empty for native host tools).

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
| `/tool [id]`                  | List recent tool calls or expand one transcript   |
| `/output [id]`                | Alias for `/tool`                                 |
| `/chat [count]`               | Show the current Commander chat thread            |
| `/details [mode]`             | Set live output detail: `compact`, `preview`, or `verbose` |
| `/status`                     | Backend / model / active engagement status        |
| `/config` · `/config reload`  | Show config · force backend to re-read `.env`     |
| `/reconnect`                  | Re-read `.env` and reconnect to `API_BASE_URL`    |
| `/reset` · `/clear` · `/exit` | Clear conversation · clear screen · exit          |

`/scan <target> [phase]` binds an engagement so `/findings` and prompts know the
target. You can also just **type natural-language prompts** — these go to the
**Commander**, a conversational brain that owns the conductor: it answers, runs one
probe, or launches the full recon→vuln→exploit pipeline in the background and keeps
chatting so you can steer it ("hit the sister domains harder", "status", "stop").
During a run the CLI streams commander decisions, live tool start/finish, and
per-phase reports.

Set or switch your LLM provider/key either manually in .env or at runtime with
`POST /api/v1/config/llm` `{"model": "...", "api_key": "...", "api_base": "..."}` —
the Settings surface GUI uses. The chat thread is persisted server-side per
engagement (`GET /api/v1/agent/conversation/{engagement_id}`), so the CLI and dashboard share one conversation.

### Seeing which tools you have

Tool availability is environment-aware: the backend probes each binary in whatever
execution mode is active (Kali container or host). Surface it with:

- **CLI:** `/tools` — a table of every tool with `installed` / `missing`.
- **MCP / harness:** the `platform_tools` tool, or `GET /api/v1/tools/catalog`
  (returns per-tool `installed` plus a summary count).

The agent plans around what's present, so a partial toolset still works — you just
get fewer techniques where a tool is missing.

## Adding your own skills (drop-in, zero code)

Skills are markdown files under `skills/<phase>/` that steer the agent's methodology
for a phase. Both executors index them by their YAML frontmatter **description** and
surface the descriptions for the *active* phase every turn, pulling full text on
demand — so a well-described skill can't be missed, and adding more never bloats the
prompt.

To add one, drop a file into the right phase folder with frontmatter:

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

- **`phase`** is which phase it appears in: `recon`, `network`, `web`, `vuln`,
  `exploit`, `osint`, `commander`, or `shared` (always-relevant). The folder you drop
  it in usually matches, but the `phase:` field is authoritative — so a file under
  `skills/custom/` with `phase: web` shows up during the web phase too.
- **`description`** is the single most important field: it's what the LLM reads to
  decide whether to open the skill. Make it concrete (when to use it + what it does).
- No restart or code change needed — the registry re-reads `skills/` on each request.

Verify it's indexed: `GET /api/v1/capabilities/skills-index?phase=web` (or
`platform_skills(phase="web")` from an MCP harness) — your skill's `name` and
`description` should appear.

## MCP Client Configuration (Alternate Approach)

Connect your AI client directly to the platform via MCP. All clients use the same MCP server at `platform-mcp/server.py`. Below are setup guides for some harnesses, setup in others is similar.

### OpenCode

CLI recommended instead of GUI for detailed commands outputs

Edit `~/.config/opencode/opencode.json` (global config — works in any project):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "osprey": {
      "type": "local",
      "command": ["python", "C:\\path\\to\\osprey\\platform-mcp\\server.py"],
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

Replace `C:\\path\\to` with the absolute path to the project. The global config makes `osprey` tools available in any repository you open with OpenCode. Verify with `/tools` in the chat — you should see all MCP tools listed.

### Claude Desktop (native MCP support)

In Claude Desktop app, go to Settings -> Developer -> Edit Config -> Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osprey": {
      "command": "python",
      "args": [
        "C:\\path\\to\\osprey\\platform-mcp\\server.py"
      ],
      "cwd": "C:\\path\\to\\osprey",
      "env": {
        "PENTEST_API_BASE": "http://localhost:9000",
        "PENTEST_QUICK_TIMEOUT": "30",
        "PENTEST_HTTP_TIMEOUT": "900"
      }
    }
  }
}
```

Replace `C:\\path\\to` with your actual project path. You should see `osprey` listed as a running MCP server in Claude's settings.

### ChatGPT Desktop

You can configure your MCP server either from the graphical interface or directly through `config.toml`.

#### Option 1 (Recommended): GUI Configuration

Open Settings → Plugins → MCPs → Add Server

Configure the server as follows.

##### Name: osprey

##### Type: STDIO

##### Command

System Python:

```
python
```

or preferably your virtual environment:

```
C:\path\to\osprey\.venv\Scripts\python.exe
```

##### Arguments

```
C:\path\to\osprey\platform-mcp\server.py
```

##### Environment Variables

| Variable | Value |
|----------|-------|
| PENTEST_API_BASE | http://localhost:9000 |
| PENTEST_QUICK_TIMEOUT | 30 |
| PENTEST_HTTP_TIMEOUT | 900 |

##### Working Directory

```
C:\path\to\osprey
```

Click **Save**.

If the configuration is valid, ChatGPT Desktop will automatically launch the MCP server whenever it is needed.

---

#### Option 2: config.toml

Instead of using the GUI, you can edit ChatGPT Desktop's `config.toml`.

Add:

```toml
[mcp_servers.osprey]
command = "python"

args = [
    "C:\\path\\to\\osprey\\platform-mcp\\server.py"
]

cwd = "C:\\path\\to\\osprey"

[mcp_servers.osprey.env]
PENTEST_API_BASE = "http://localhost:9000"
PENTEST_QUICK_TIMEOUT = "30"
PENTEST_HTTP_TIMEOUT = "900"
```

If using a virtual environment, replace the command with:

```toml
command = "C:\\path\\to\\osprey\\.venv\\Scripts\\python.exe"
```

Restart ChatGPT Desktop after editing `config.toml`.

For the best integrated experience, use **Hermes** or **OpenCode**. **Claude Code** if you have completed Cyber Verification Program or **ChatGPT** if approved OpenAI's Trusted Access for Cyber (TAC) access.

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

- `backend/src/osprey/main.py` — FastAPI app
- `backend/src/osprey/core/config.py` — Runtime settings
- `backend/src/osprey/api/v1/router.py` — API route registration
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

See [`docs/STATUS_AND_ROADMAP.md`](docs/STATUS_AND_ROADMAP.md) for the current status and the active reliability plan. Near-term focus: real scope/ROE governance, durable jobs + attempt history, graph/evidence provenance hardening, and the killchain engine.

## Contributing

Contributions are welcome! Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines on reporting issues, suggesting features, and submitting pull requests.

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [`LICENSE`](LICENSE) file for details.

