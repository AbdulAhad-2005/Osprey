# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
# Pass -Gui to also install the Operator Console (gui/) web dashboard deps.
param(
    [switch]$Gui
)
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
    Write-Host ""
    Write-Host "Virtual environment creation failed (.venv\Scripts\python.exe not found)." -ForegroundColor Red
    Write-Host "This usually means:" -ForegroundColor Yellow
    Write-Host "  - the Python you have is the Microsoft Store app (its venv support is" -ForegroundColor Yellow
    Write-Host "    sandboxed/unreliable) - install the real one from python.org or:" -ForegroundColor Yellow
    Write-Host "    winget install Python.Python.3.12" -ForegroundColor White
    Write-Host "  - or a prior failed run left a broken .venv\ - delete it and re-run:" -ForegroundColor Yellow
    Write-Host "    Remove-Item -Recurse -Force .venv" -ForegroundColor White
    exit 1
}

Write-Host "Upgrading pip..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip --quiet

Write-Host "Installing backend and CLI in editable mode..." -ForegroundColor Cyan
& $venvPython -m pip install -e ./agent_core -e "./backend[dev]" -e ./cli

if (Test-Path "mcp-servers/requirements.txt") {
    Write-Host "Installing native tool-wrapper dependencies..." -ForegroundColor Cyan
    & $venvPython -m pip install -r mcp-servers/requirements.txt --quiet
}

# Operator Console (web dashboard) — optional, needs Node.js.
if ($Gui) {
    Write-Host ""
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "Installing Operator Console (gui/) dependencies..." -ForegroundColor Cyan
        Push-Location gui
        try { & npm install } finally { Pop-Location }
        Write-Host "GUI ready. Start it with:  cd gui; npm run dev   # http://localhost:3100" -ForegroundColor White
    } else {
        Write-Host "Skipping GUI: Node.js/npm not found on PATH. Install Node 18.18+ from https://nodejs.org, then: cd gui; npm install; npm run dev" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Start the backend  : powershell -ExecutionPolicy Bypass -File scripts\serve.ps1" -ForegroundColor White
Write-Host "Run the Osprey CLI : .\.venv\Scripts\Activate.ps1 ; osprey" -ForegroundColor White
if ($Gui) { Write-Host "The Operator Console (web GUI) runs from gui/ - see above." -ForegroundColor White }
