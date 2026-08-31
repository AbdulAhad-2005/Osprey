#!/usr/bin/env bash
# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:  bash scripts/setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip

# Backend (with dev extras: pytest, ruff, httpx) + CLI, both editable.
pip install -e "./backend[dev]" -e ./cli

# Native tool-wrapper deps — only needed if you run tools on the host instead of
# the Kali container. Safe to install regardless.
pip install -r mcp-servers/requirements.txt

echo
echo "Setup complete. Activate the environment with:"
echo "    source .venv/bin/activate"
echo "Then run the backend (uvicorn pentest_platform.main:app --port 9000) and Osprey CLI (osprey)."
