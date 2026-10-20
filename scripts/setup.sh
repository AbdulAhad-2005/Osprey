#!/usr/bin/env bash
# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:  bash scripts/setup.sh
# Pass --gui to also install the Operator Console (gui/) web dashboard deps.
set -euo pipefail

cd "$(dirname "$0")/.."

WITH_GUI=0
for arg in "$@"; do
  case "$arg" in
    --gui) WITH_GUI=1 ;;
    *) echo "Unknown option: $arg (supported: --gui)"; exit 1 ;;
  esac
done

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip

# Backend (with dev extras: pytest, ruff, httpx) + CLI, both editable.
pip install -e ./agent_core -e "./backend[dev]" -e ./cli

# Native tool-wrapper deps — only needed if you run tools on the host instead of
# the Kali container. Safe to install regardless.
pip install -r mcp-servers/requirements.txt

# Operator Console (web dashboard) — optional, needs Node.js.
if [ "$WITH_GUI" -eq 1 ]; then
  echo
  if command -v npm >/dev/null 2>&1; then
    echo "Installing Operator Console (gui/) dependencies..."
    ( cd gui && npm install )
    echo "GUI ready. Start it with:  cd gui && npm run dev   # http://localhost:3100"
  else
    echo "Skipping GUI: Node.js/npm not found on PATH. Install Node 18.18+ from https://nodejs.org, then: cd gui && npm install && npm run dev"
  fi
fi

echo
echo "Setup complete. Activate the environment with:"
echo "    source .venv/bin/activate"
echo "Then run the backend (uvicorn osprey.main:app --port 9000) and Osprey CLI (osprey)."
[ "$WITH_GUI" -eq 1 ] && echo "The Operator Console (web GUI) runs from gui/ — see above."
