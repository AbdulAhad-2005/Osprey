# Start the MCP gateway over HTTP (streamable-http) locally - no Docker.
#
# Most MCP clients (Claude Desktop, Cursor, OpenCode) launch platform-mcp
# themselves over stdio instead (see mcp-config.json / README). This is for
# a client that only accepts a server URL, not a launch command - same
# gateway, same tools, just reachable at a URL instead of spawned as a
# subprocess. Equivalent to Docker mode's `docker compose --profile
# mcp-http up -d` (see docker-compose.yml's mcp-gateway service).
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\serve-mcp-http.ps1 [-HostName 0.0.0.0] [-Port 9100]
# Keep this running in its own terminal; the backend (scripts\serve.ps1)
# needs to be running separately too.
param(
    [string]$HostName = "0.0.0.0",
    [int]$Port = 9100
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "No .venv found here. Run the setup wizard first:" -ForegroundColor Red
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\install.ps1" -ForegroundColor White
    exit 1
}

# try/catch: PS5.1 promotes native stderr to a terminating error under EAP=Stop.
try { & $venvPython -c "import mcp, httpx" 2>$null } catch { }
if ($LASTEXITCODE -ne 0) {
    Write-Host "MCP deps aren't installed in .venv. Run:  pip install -r platform-mcp\requirements.txt" -ForegroundColor Red
    exit 1
}

$env:MCP_TRANSPORT = "streamable-http"
$env:MCP_HTTP_HOST = $HostName
$env:MCP_HTTP_PORT = "$Port"
& $venvPython platform-mcp\server.py
exit $LASTEXITCODE
