# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
# Pass -Gui to also install the Operator Console (gui/) web dashboard deps.
param(
    [switch]$Gui
)
$ErrorActionPreference = "Stop"

$RootDir = Join-Path $PSScriptRoot ".."
Set-Location $RootDir
$RootDir = (Get-Location).Path
. (Join-Path $PSScriptRoot "lib_local_python.ps1")

$venvPython = ".\.venv\Scripts\python.exe"
if ((Test-Path $venvPython) -and (Test-LocalVenvPythonIsWrong (Resolve-Path $venvPython).Path)) {
    Write-Host "The existing .venv's Python doesn't match what this build's precompiled runtime needs." -ForegroundColor Yellow
    Write-Host "Recreating .venv with a matching interpreter..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force ".venv" -ErrorAction SilentlyContinue
}

if (-not (Test-Path ".venv")) {
    $pyExe = Resolve-LocalVenvPython
    if (-not $pyExe) { exit 1 }
    Write-Host "Using Python: $pyExe" -ForegroundColor Cyan
    Write-Host "Creating .venv virtual environment..." -ForegroundColor Cyan
    & $pyExe -m venv .venv
}
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

# README promises `osprey` works "from any working directory" — that's only
# true if THIS venv's Scripts dir (where pip just wrote osprey.exe) is on
# PATH. Pip install alone never does that (confirmed live: a fresh per-user
# Python install left Scripts off PATH entirely, so `osprey` was
# "not recognized" even though osprey.exe existed right there). Pin it to
# THIS project's own .venv rather than whatever global interpreter happens to
# be active, so `osprey` always resolves to a dependency set that matches
# this checkout instead of silently drifting
$venvScripts = (Resolve-Path ".\.venv\Scripts").Path
$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
$pathEntries = $userPath -split ';' | Where-Object { $_ }
if ($pathEntries -notcontains $venvScripts) {
    Write-Host "Adding $venvScripts to your user PATH so 'osprey' works from any terminal..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable('PATH', "$userPath;$venvScripts", 'User')
    Write-Host "Done — open a NEW terminal window for this to take effect." -ForegroundColor Yellow
} else {
    Write-Host "$venvScripts is already on your user PATH." -ForegroundColor DarkGray
}

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
Write-Host "Run the Osprey CLI : osprey   (open a new terminal first if PATH was just updated above)" -ForegroundColor White
if ($Gui) { Write-Host "The Operator Console (web GUI) runs from gui/ - see above." -ForegroundColor White }
