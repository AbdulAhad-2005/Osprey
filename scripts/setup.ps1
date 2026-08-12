# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

python -m venv .venv
& .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip

# Backend (with dev extras: pytest, ruff, httpx) + CLI, both editable.
pip install -e "./backend[dev]" -e ./cli

# Native tool-wrapper deps — only needed if you run tools on the host instead of
# the Kali container. Safe to install regardless.
pip install -r mcp-servers/requirements.txt

Write-Host ""
Write-Host "Setup complete. Activate the environment with:"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "Then run the backend (uvicorn pentest_platform.main:app --port 9000) and the CLI (python -m cli)."
