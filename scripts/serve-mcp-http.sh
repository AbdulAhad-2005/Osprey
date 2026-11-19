#!/usr/bin/env bash
# Start the MCP gateway over HTTP (streamable-http) locally — no Docker.
#
# Most MCP clients (Claude Desktop, Cursor, OpenCode) launch platform-mcp
# themselves over stdio instead (see mcp-config.json / README). This is for
# a client that only accepts a server URL, not a launch command — same
# gateway, same tools, just reachable at a URL instead of spawned as a
# subprocess. Equivalent to Docker mode's `docker compose --profile
# mcp-http up -d` (see docker-compose.yml's mcp-gateway service).
#
# Usage: bash scripts/serve-mcp-http.sh [--host 0.0.0.0] [--port 9100]
# Keep this running in its own terminal; the backend (scripts/serve.sh) needs
# to be running separately too.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif [ -x ".venv/Scripts/python.exe" ]; then
  PY=".venv/Scripts/python.exe"
else
  echo "No .venv found here. Run the setup wizard first:" >&2
  echo "    bash scripts/install.sh      # or: bash scripts/setup.sh" >&2
  exit 1
fi

if ! "$PY" -c "import mcp, httpx" >/dev/null 2>&1; then
  echo "MCP deps aren't installed in .venv. Run:  \"$PY\" -m pip install -r platform-mcp/requirements.txt" >&2
  exit 1
fi

HOST="0.0.0.0"
PORT="9100"
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

export MCP_TRANSPORT=streamable-http
export MCP_HTTP_HOST="$HOST"
export MCP_HTTP_PORT="$PORT"
exec "$PY" platform-mcp/server.py
