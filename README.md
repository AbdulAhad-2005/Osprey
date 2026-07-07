# Autonomous Pentesting Tool

An autonomous AI penetration testing platform with a FastAPI backend and a Python CLI operator interface.

## Architecture

- `backend/` — FastAPI control plane, API endpoints, database models, workflow logic
- `cli/` — Python CLI tool (prompt_toolkit) for interacting with the platform
- `mcp-servers/` — Capability-based tool adapters (planned)
- `docker-compose.yml` — Local dev stack with Postgres

## Quick start

### 1. Start the backend (Docker or local)

**Docker:**
```bash
cp .env.example .env
docker compose up --build
```
Backend runs on port 9000.

**Local:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e .
uvicorn pentest_platform.main:app --host 0.0.0.0 --port 9000
```

### 2. Run the CLI

The CLI uses the same venv as the backend:
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

### 3. CLI commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/health` | Check backend service health |
| `/tools` | List available MCP tools |
| `/models` | List configured LLM models |
| `/scan <target>` | Start a scan against a target |
| `/engage list` | List all engagements |
| `/engage new <target>` | Create a new engagement |
| `/findings` | Show discovered findings |
| `/status` | Show current session status |
| `/config` | Show current configuration |
| `/clear` | Clear the terminal screen |
| `/exit` | Exit the CLI |

You can also type natural language prompts directly to interact with the agent pipeline.

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

## Next steps

1. Add the graph and audit models to the backend
2. Introduce Temporal workflows when the orchestration layer is ready
3. Build the first MCP server around recon and target expansion
4. Wire the CLI to the agent pipeline for real-time scan interaction

## Tools Analyzed and Summary:
https://docs.google.com/document/d/1XqAMlZ9ErRywIHvR0FinwqmysCgSqYzIGtXoqmlsDGc/edit?usp=sharing
