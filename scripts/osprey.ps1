# Launch the Osprey operator CLI (Windows) — works whether the backend runs
# in Docker or the CLI was installed into a local .venv.
#
# 1. Full/Lean Docker mode: transparently runs inside the `osprey-backend`
#    container (already has the CLI installed, zero host dependencies).
# 2. Local mode: runs through the host .venv created by the setup wizard.
#
# Usage: osprey [any CLI args/flags]  (see `osprey --help`)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$RootDir = (Get-Location).Path
. (Join-Path $PSScriptRoot "lib_local_python.ps1")

# 1. Check if the osprey-backend Docker container is running.
$dockerAvailable = $false
if (Get-Command docker -ErrorAction SilentlyContinue) {
    try { docker ps *> $null; if ($LASTEXITCODE -eq 0) { $dockerAvailable = $true } } catch {}
}

if ($dockerAvailable) {
    $names = & docker ps --format '{{.Names}}' 2>$null
    if ($names -contains "osprey-backend") {
        $ttyFlags = "-i"
        if ([Console]::IsInputRedirected -eq $false -and [Console]::IsOutputRedirected -eq $false) {
            $ttyFlags = "-it"
        }
        & docker exec $ttyFlags -e API_BASE_URL=http://localhost:9000 osprey-backend osprey @args
        exit $LASTEXITCODE
    }
}

# 2. Fallback to local .venv.
$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Osprey backend container is not running and no local .venv was found." -ForegroundColor Red
    Write-Host "Run the setup wizard first:" -ForegroundColor White
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\install.ps1" -ForegroundColor White
    exit 1
}

# Check Python version compatibility for a downstream PyArmor-obfuscated
# build (any mismatch, not just a newer host Python -- an older one is just
# as broken). Never present for Osprey itself, so this is a no-op here.
if (Test-LocalVenvPythonIsWrong (Resolve-Path $venvPython).Path) {
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "  [!] This .venv's Python doesn't match what this build's precompiled runtime needs." -ForegroundColor Red
    Write-Host "      Re-run the setup wizard to fix it (it will recreate .venv automatically):" -ForegroundColor White
    Write-Host "          powershell -ExecutionPolicy Bypass -File scripts\setup.ps1" -ForegroundColor White
    Write-Host "      Or run via Docker (Full Docker mode), which bundles its own Python:" -ForegroundColor White
    Write-Host "          docker compose --profile kali up -d" -ForegroundColor White
    Write-Host "          osprey" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Red
    exit 1
}

# try/catch: PS5.1 promotes native stderr to a terminating error under EAP=Stop.
try { & $venvPython -c "import cli" 2>$null } catch { }
if ($LASTEXITCODE -ne 0) {
    Write-Host "The CLI isn't installed in .venv. Run:  pip install -e .\cli" -ForegroundColor Red
    Write-Host "(or re-run  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 )" -ForegroundColor White
    exit 1
}

& $venvPython -m cli @args
exit $LASTEXITCODE
