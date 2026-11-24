# Start the Osprey backend locally - no Docker, no venv activation needed.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\serve.ps1 [--host 0.0.0.0] [--port 9000] [--reload]
#
# This is the "just start it" command for the Fully-Local (SQLite / no-Docker)
# setup path: it finds the venv scripts/setup.ps1 created and runs the backend
# directly through it, so you never have to remember `.venv\Scripts\Activate.ps1`
# followed by a uvicorn invocation.
$ErrorActionPreference = "Stop"
$RootDir = Join-Path $PSScriptRoot ".."
Set-Location $RootDir
$RootDir = (Get-Location).Path
. (Join-Path $PSScriptRoot "lib_local_python.ps1")

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "No .venv found here. Run the setup wizard first:" -ForegroundColor Red
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\install.ps1" -ForegroundColor White
    exit 1
}

if (Test-LocalVenvPythonIsWrong (Resolve-Path $venvPython).Path) {
    Write-Host "This .venv's Python doesn't match what this build's precompiled runtime needs." -ForegroundColor Red
    Write-Host "Re-run the setup wizard to fix it:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1" -ForegroundColor White
    exit 1
}

# Distinguish "genuinely not installed yet" from "installed, but the import
# itself failed" (e.g. a PyArmor runtime/Python mismatch) — the latter used
# to get misreported as "not installed", sending people in circles
# reinstalling something that wasn't the actual problem.
# try/catch: PS5.1 promotes native stderr to a terminating error under EAP=Stop.
$importErr = ""
try { $importErr = (& $venvPython -c "import osprey" 2>&1 | Out-String) } catch { $importErr = "$_" }
if ($LASTEXITCODE -ne 0) {
    if ($importErr -match "ModuleNotFoundError") {
        Write-Host "The backend isn't installed in .venv. Run:  pip install -e .\backend" -ForegroundColor Red
        Write-Host "(or re-run  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 )" -ForegroundColor White
    } else {
        Write-Host "The backend is installed, but failed to import:" -ForegroundColor Red
        Write-Host $importErr -ForegroundColor Red
    }
    exit 1
}

& $venvPython -m osprey.cli @args
