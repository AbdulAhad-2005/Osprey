# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

$pyExe = $null
foreach ($cand in @("python", "py", "python3")) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        try {
            $ver = & $cand -c "import sys; print(sys.version_info.major)" 2>$null
            if ($ver -eq "3") { $pyExe = $cand; break }
        } catch {}
    }
}

if (-not $pyExe) {
    Write-Error "Python 3 is not installed or not on PATH. Please install Python 3.11+."
    exit 1
}

Write-Host "Using Python: $pyExe" -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    Write-Host "Creating .venv virtual environment..." -ForegroundColor Cyan
    & $pyExe -m venv .venv
}

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Error "Virtual environment creation failed (.venv\Scripts\python.exe not found)."
    exit 1
}

Write-Host "Upgrading pip..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip --quiet

Write-Host "Installing backend and CLI in editable mode..." -ForegroundColor Cyan
& $venvPython -m pip install -e "./backend[dev]" -e ./cli

if (Test-Path "mcp-servers/requirements.txt") {
    Write-Host "Installing native tool-wrapper dependencies..." -ForegroundColor Cyan
    & $venvPython -m pip install -r mcp-servers/requirements.txt --quiet
}

Write-Host ""
Write-Host "Setup complete. Activate the environment with:" -ForegroundColor Green
Write-Host "    .\.venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "Then run the backend (uvicorn osprey.main:app --port 9000) or Osprey CLI (osprey)." -ForegroundColor White
