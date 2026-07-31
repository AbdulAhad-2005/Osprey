# Autonomous Pentesting Tool

An autonomous AI penetration testing platform with a FastAPI backend and a Python CLI operator interface.

## Architecture

- `backend/` — FastAPI control plane, API endpoints, database models, workflow logic
- `cli/` — Python CLI tool (prompt_toolkit) for interacting with the platform
- `mcp-servers/` — Capability-based tool adapters for network, recon, and web modules
- `platform-mcp/` — MCP gateway server connecting AI clients to the platform
- `docker-compose.yml` — Full stack: Postgres + Kali Linux (90+ tools) + FastAPI backend

## Quick start

### 1. Start the stack (Docker — recommended)

This brings up Postgres, a Kali Linux container with all pentest tools pre-installed, and the backend in one shot:

```bash
cp .env.example .env
# Edit .env with your LLM API key (see comments in the file)
docker compose up --build
```

**What you get:**
- `postgres` — database (port 5433 mapped to host)
- `kali-tools` — Kali container with 90+ tools (nmap, metasploit, subfinder, httpx, rustscan, etc.)
- `backend` — FastAPI control plane (port 9000)

> **No WSL / VirtualBox needed on Windows.** The `kali-tools` service builds a Kali image directly via Docker. All tools run inside the container, accessed by the backend via `docker exec`. This is the recommended approach.

### 2. Run database migrations

With the stack running, apply Alembic migrations to set up the schema:

```bash
docker compose exec backend alembic upgrade head
```

### 3. Start the backend locally (alternative)

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e .
uvicorn pentest_platform.main:app --host 0.0.0.0 --port 9000
```

Requires Postgres running locally (or via `docker compose up postgres`).

### 4. Run the CLI

```bash
cd cli
pip install -e .
```

From the project root:

```bash
python -m cli
```

The CLI connects to `http://localhost:9000` by default. Override with:

```bash
set API_BASE_URL=http://localhost:9000
python -m cli
```

### 5. CLI commands

| Command                  | Description                   |
| ------------------------ | ----------------------------- |
| `/help`                | Show available commands       |
| `/health`              | Check backend service health  |
| `/tools`               | List available MCP tools      |
| `/models`              | List configured LLM models    |
| `/scan <target>`       | Start a scan against a target |
| `/engage list`         | List all engagements          |
| `/engage new <target>` | Create a new engagement       |
| `/findings`            | Show discovered findings      |
| `/status`              | Show current session status   |
| `/config`              | Show current configuration    |
| `/clear`               | Clear the terminal screen     |
| `/exit`                | Exit the CLI                  |

You can also type natural language prompts directly to interact with the agent pipeline.

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

