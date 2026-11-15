#!/usr/bin/env bash
# Start the Osprey backend locally — no Docker, no venv activation needed.
# Usage: bash scripts/serve.sh [--host 0.0.0.0] [--port 9000] [--reload]
#
# This is the "just start it" command for the Fully-Local (SQLite / no-Docker)
# setup path: it finds the venv scripts/setup.sh (or setup.ps1) created and
# runs the backend directly through it, so you never have to remember
# `source .venv/bin/activate` followed by a uvicorn invocation.
set -euo pipefail
cd "$(dirname "$0")/.."

# A venv's python lives at .venv/bin/python on Linux/macOS/WSL, but at
# .venv/Scripts/python.exe when it was created by a native Windows Python —
# which happens even if you're invoking THIS script from Git Bash, since
# `python -m venv` lays itself out by OS, not by which shell ran it. Check
# both, so `bash scripts/serve.sh` works regardless of which setup script (or
# which shell) created the venv.
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif [ -x ".venv/Scripts/python.exe" ]; then
  PY=".venv/Scripts/python.exe"
else
  echo "No .venv found here. Run the setup wizard first:" >&2
  echo "    bash scripts/install.sh      # or: bash scripts/setup.sh" >&2
  echo "    (on native Windows, prefer the .ps1 versions instead)" >&2
  exit 1
fi

if ! "$PY" -c "import osprey" >/dev/null 2>&1; then
  echo "The backend isn't installed in .venv. Run:  \"$PY\" -m pip install -e ./backend" >&2
  echo "(or re-run  bash scripts/setup.sh  to install everything)" >&2
  exit 1
fi

exec "$PY" -m osprey.cli "$@"
