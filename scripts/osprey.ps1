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
$RootDir = Get-Location

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

# Check Python version compatibility for a downstream PyArmor-obfuscated build.
if (Get-ChildItem -Path $RootDir -Filter "pyarmor_runtime_*" -Directory -ErrorAction SilentlyContinue) {
    $pyMinor = & $venvPython -c "import sys; print(sys.version_info.minor)" 2>$null
    if ($pyMinor -and [int]$pyMinor -ge 13) {
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "  [!] Host Python 3.$pyMinor detected." -ForegroundColor Red
        Write-Host "      The bundled runtime requires Python 3.12 for local host execution." -ForegroundColor Red
        Write-Host "      Recommended: Run via Docker (Full Docker mode), which uses Python 3.12:" -ForegroundColor White
        Write-Host "          docker compose --profile kali up -d" -ForegroundColor White
        Write-Host "          osprey" -ForegroundColor White
        Write-Host "================================================================================" -ForegroundColor Red
        exit 1
    }
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
