#!/usr/bin/env bash
# Start the Osprey backend locally — no Docker, no venv activation needed.
# Usage: bash scripts/serve.sh [--host 0.0.0.0] [--port 9000] [--reload]
#
# This is the "just start it" command for the Fully-Local (SQLite / no-Docker)
# setup path: it finds the venv scripts/setup.sh (or setup.ps1) created and
# runs the backend directly through it, so you never have to remember
# `source .venv/bin/activate` followed by a uvicorn invocation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"
. "$SCRIPT_DIR/lib_local_python.sh"

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

if local_venv_python_is_wrong "$PY"; then
  echo "This .venv's Python doesn't match what this build's precompiled runtime needs." >&2
  echo "Re-run the setup wizard to fix it:  bash scripts/setup.sh   (or scripts/install.sh)" >&2
  exit 1
fi

# Distinguish "genuinely not installed yet" from "installed, but the import
# itself failed" (e.g. a PyArmor runtime/Python mismatch) — the latter used to
# get misreported as "not installed", sending people in circles reinstalling
# something that wasn't the actual problem.
import_err=""
if ! import_err="$("$PY" -c "import osprey" 2>&1)"; then
  if printf '%s' "$import_err" | grep -q "ModuleNotFoundError"; then
    echo "The backend isn't installed in .venv. Run:  \"$PY\" -m pip install -e ./backend" >&2
    echo "(or re-run  bash scripts/setup.sh  to install everything)" >&2
  else
    echo "The backend is installed, but failed to import:" >&2
    echo "$import_err" >&2
  fi
  exit 1
fi

exec "$PY" -m osprey.cli "$@"
