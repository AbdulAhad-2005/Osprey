# Start the Osprey backend locally - no Docker, no venv activation needed.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\serve.ps1 [--host 0.0.0.0] [--port 9000] [--reload]
#
# This is the "just start it" command for the Fully-Local (SQLite / no-Docker)
# setup path: it finds the venv scripts/setup.ps1 created and runs the backend
# directly through it, so you never have to remember `.venv\Scripts\Activate.ps1`
# followed by a uvicorn invocation.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "No .venv found here. Run the setup wizard first:" -ForegroundColor Red
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\install.ps1" -ForegroundColor White
    exit 1
}

& $venvPython -c "import osprey" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "The backend isn't installed in .venv. Run:  pip install -e .\backend" -ForegroundColor Red
    Write-Host "(or re-run  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 )" -ForegroundColor White
    exit 1
}

& $venvPython -m osprey.cli @args
