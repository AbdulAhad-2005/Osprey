# ==============================================================================
# Osprey - Guided Interactive Setup & Onboarding Wizard (Windows PowerShell)
# ==============================================================================
#
# Walks through:
#   [1/5] Tool execution & infrastructure mode (Full Docker / Lean / Hybrid / Local)
#   [2/5] Tool environment initialization & health checks
#   [3/5] Usage mode selection (Built-in CLI, AI Harness via MCP, or Both)
#   [4/5] Model configuration (LiteLLM provider presets & API key)
#   [5/5] Optional OSINT API keys & automatic AI harness MCP configuration
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1
# ==============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$RootDir = Split-Path $ScriptDir -Parent
Set-Location $RootDir

# ── Styling & output helpers ──────────────────────────────────────────────────
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "+-------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ("|  {0,-58} |" -f $Title) -ForegroundColor Cyan
    Write-Host "+-------------------------------------------------------------+" -ForegroundColor Cyan
}

function Write-Step    { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-WarnItem{ param($m) Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-FailItem{ param($m) Write-Host "  [X]  $m" -ForegroundColor Red }
function Write-Muted   { param($m) Write-Host "       $m" -ForegroundColor DarkGray }

# ── .env upsert helper ────────────────────────────────────────────────────────
# Whole-line replace or append so values with arbitrary characters are safe.
function Set-EnvVar {
    param([string]$Key, [string]$Value, [string]$Path = ".env")
    $lines = @()
    $found = $false
    if (Test-Path $Path) {
        $lines = Get-Content $Path
    }
    $out = foreach ($line in $lines) {
        if ($line -like "$Key=*") {
            $found = $true
            "$Key=$Value"
        } else {
            $line
        }
    }
    if (-not $found) { $out += "$Key=$Value" }
    Set-Content -Path $Path -Value $out -Encoding utf8
}

function Get-EnvVar {
    param([string]$Key, [string]$Default = "", [string]$Path = ".env")
    if (-not (Test-Path $Path)) { return $Default }
    foreach ($line in (Get-Content $Path)) {
        if ($line -like "$Key=*") {
            return $line.Substring($Key.Length + 1).Trim()
        }
    }
    return $Default
}

function Test-DockerReady {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-FailItem "docker is not installed or not in PATH. Please install Docker Desktop first."
        return $false
    }
    try {
        docker info *> $null
        if ($LASTEXITCODE -ne 0) { throw "daemon unreachable" }
    } catch {
        Write-FailItem "Docker daemon is not reachable. Ensure Docker Desktop is running."
        return $false
    }
    return $true
}

function Wait-ForBackend {
    param([int]$MaxSeconds = 60)
    Write-Host -NoNewline "  Waiting for backend at http://localhost:9000/health " -ForegroundColor Cyan
    for ($i = 0; $i -lt $MaxSeconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:9000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($r.StatusCode -eq 200) {
                Write-Host ""
                Write-Success "Backend is healthy and listening on http://localhost:9000"
                return $true
            }
        } catch { }
        Write-Host -NoNewline "." -ForegroundColor DarkGray
        Start-Sleep -Seconds 1
    }
    Write-Host ""
    Write-WarnItem "Backend did not respond within $MaxSeconds seconds. It may still be starting."
    Write-WarnItem "Inspect logs using:  docker compose logs -f backend"
    return $false
}

function Resolve-PythonPath {
    if (Test-Path "$RootDir\.venv\Scripts\python.exe") {
        return "$RootDir\.venv\Scripts\python.exe"
    }
    foreach ($cand in @("python.exe", "python3.exe", "py.exe")) {
        $c = Get-Command $cand -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    return "python"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"
   ____  _____ _____  _____  ________   __
  / __ \/ ___// __ \/ __ \/ ____/\ \ / /
 / / / /\__ \/ /_/ / /_/ / __/    \ V /  
/ /_/ /___/ / ____/ _, _/ /___     / /   
\____//____/_/   /_/ |_/_____/    /_/    
Autonomous AI Offensive Security Platform
"@ -ForegroundColor Red

Write-Host "Welcome to the Osprey setup wizard. Press Ctrl+C anytime to exit." -ForegroundColor DarkGray
Write-Host "Re-running this wizard is always safe and preserves existing work.`n" -ForegroundColor DarkGray

# ── Ensure .env exists ────────────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Success "Initialized .env from .env.example"
} else {
    Write-Success "Found existing .env (will update only selected keys)"
}

# ==============================================================================
# [1/5] Execution & Tool Runtime Selection
# ==============================================================================
Write-Header "[1/5] How should Osprey & security tools run?"

Write-Host "  1) Full Docker (Recommended)" -ForegroundColor White
Write-Muted "All-in-one: Postgres DB, Backend API & 90+ Kali tools in Docker."
Write-Muted "Zero tool installation required on your host system."

Write-Host "  2) Lean Docker (Custom Tools Container)" -ForegroundColor White
Write-Muted "Postgres & Backend in Docker; tools executed via your own existing container."

Write-Host "  3) Hybrid (Docker Postgres + Local Scanners)" -ForegroundColor White
Write-Muted "Postgres runs in Docker; Backend and security scanners run on this machine."

Write-Host "  4) Fully Local, No Docker (Self-contained / SQLite)" -ForegroundColor White
Write-Muted "Backend and tools run on this machine with local SQLite database (no Docker required)."

Write-Host "  0) Manual Setup" -ForegroundColor White
Write-Muted "Keep .env as-is; I will start services manually."

$runtimeChoice = Read-Host "`nSelect execution mode [1]"
if (-not $runtimeChoice) { $runtimeChoice = "1" }

$isDockerMode = $false
$isFullDocker = $false

switch ($runtimeChoice) {
    "1" {
        $isDockerMode = $true
        $isFullDocker = $true
        if (-not (Test-DockerReady)) { exit 1 }

        Write-Header "Full Docker: Kali Image Source"
        Write-Host "  1) Pull prebuilt Kali image from Docker Hub (Fast, ~10-30 min, Recommended)" -ForegroundColor White
        Write-Muted "Image: ospreytools/osprey-kali:latest (prebuilt with all 90+ tools)"
        Write-Host "  2) Build Kali image from source (Slow, ~40-60 min, needs ~20GB disk)" -ForegroundColor White
        Write-Muted "Compiles all tools locally via kali-tools/Dockerfile"

        $imgChoice = Read-Host "`nSelect image source [1]"
        if (-not $imgChoice) { $imgChoice = "1" }

        Set-EnvVar -Key "KALI_CONTAINER" -Value "osprey-kali"
        Set-EnvVar -Key "DATABASE_URL" -Value "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

        if ($imgChoice -eq "2") {
            Write-Step "Building Kali image from source and starting stack..."
            Write-WarnItem "This build compiles heavy tools and may take 40-60 minutes on cold runs."
            docker compose --profile kali -f docker-compose.yml -f docker-compose.build.yml up -d --build
            if ($LASTEXITCODE -ne 0) {
                Write-FailItem "Build/compose failed. Ensure Docker has adequate disk space (~16GB free)."
                exit 1
            }
        } else {
            Set-EnvVar -Key "OSPREY_KALI_IMAGE" -Value "ospreytools/osprey-kali:latest"
            Write-Step "Pulling prebuilt image (ospreytools/osprey-kali:latest) & launching stack..."
            docker compose --profile kali up -d
            if ($LASTEXITCODE -ne 0) {
                Write-FailItem "docker compose failed. Please check the error output above."
                exit 1
            }
        }
        Write-Success "Docker stack started."
        Wait-ForBackend | Out-Null
    }

    "2" {
        $isDockerMode = $true
        if (-not (Test-DockerReady)) { exit 1 }
        $currentCont = Get-EnvVar -Key "KALI_CONTAINER" -Default "my-kali-container"
        $toolsCont = Read-Host "`nEnter the name of your running tools container [$currentCont]"
        if (-not $toolsCont) { $toolsCont = $currentCont }
        if (-not $toolsCont) { Write-FailItem "Container name cannot be empty."; exit 1 }

        Set-EnvVar -Key "KALI_CONTAINER" -Value $toolsCont
        Set-EnvVar -Key "DATABASE_URL" -Value "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

        Write-Step "Starting Postgres + Backend in Docker (targeting container $toolsCont)..."
        docker compose up -d
        if ($LASTEXITCODE -ne 0) { Write-FailItem "docker compose failed."; exit 1 }
        Write-Success "Stack started. Tools will be executed into container: $toolsCont"
        Wait-ForBackend | Out-Null
    }

    "3" {
        if (-not (Test-DockerReady)) { exit 1 }
        Set-EnvVar -Key "DATABASE_URL" -Value "postgresql+psycopg://pentest:pentest@localhost:5432/pentest"
        Set-EnvVar -Key "KALI_CONTAINER" -Value ""

        Write-Step "Starting Postgres database container..."
        docker compose up -d postgres
        if ($LASTEXITCODE -ne 0) { Write-FailItem "Failed to start Postgres container."; exit 1 }
        Write-Success "Postgres container is active on localhost:5432"

        Write-Step "Setting up local Python virtual environment for backend & tools..."
        & "$ScriptDir\setup.ps1"
    }

    "4" {
        Set-EnvVar -Key "DATABASE_URL" -Value "sqlite:///./pentest.db"
        Set-EnvVar -Key "KALI_CONTAINER" -Value ""

        Write-Step "Configured SQLite local database (pentest.db)."
        Write-Step "Setting up local Python virtual environment..."
        & "$ScriptDir\setup.ps1"
    }

    "0" {
        Write-Success "Manual mode selected. Preserved current .env."
    }

    default {
        Write-FailItem "Unrecognized option: $runtimeChoice"
        exit 1
    }
}

# ==============================================================================
# [2/5] Tool Environment Detection (For Local/Hybrid Modes)
# ==============================================================================
if ($runtimeChoice -in @("3", "4")) {
    Write-Header "[2/5] Host Tool Availability & Scanner Detection"
    Write-Host "Scanning for native security tools on your PATH..." -ForegroundColor Cyan

    $toolsToCheck = @(
        @{ Name = "nmap";        Type = "Port / Network Scanner";       Cmd = "nmap" },
        @{ Name = "subfinder";   Type = "Subdomain Discovery";          Cmd = "subfinder" },
        @{ Name = "httpx";       Type = "HTTP Probe & Fingerprinting";  Cmd = "httpx" },
        @{ Name = "naabu";       Type = "Port Scanner";                 Cmd = "naabu" },
        @{ Name = "dnsx";        Type = "DNS Resolver / PTR";           Cmd = "dnsx" },
        @{ Name = "tlsx";        Type = "TLS Inspection";               Cmd = "tlsx" },
        @{ Name = "katana";      Type = "Web Crawler";                  Cmd = "katana" },
        @{ Name = "nuclei";      Type = "Vulnerability Scanner";        Cmd = "nuclei" },
        @{ Name = "whois";       Type = "WHOIS / ASN Enum";             Cmd = "whois" },
        @{ Name = "searchsploit";Type = "Exploit Database Lookup";      Cmd = "searchsploit" }
    )

    $missingTools = @()
    foreach ($t in $toolsToCheck) {
        $cmdFound = Get-Command $t.Cmd -ErrorAction SilentlyContinue
        if ($cmdFound) {
            Write-Host ("  [+] {0,-14} : Found ({1})" -f $t.Name, $t.Type) -ForegroundColor Green
        } else {
            Write-Host ("  [!] {0,-14} : Missing ({1})" -f $t.Name, $t.Type) -ForegroundColor Yellow
            $missingTools += $t
        }
    }

    if ($missingTools.Count -eq 0) {
        Write-Success "All primary security scanners are present on this machine!"
    } else {
        Write-Host ""
        Write-WarnItem "$($missingTools.Count) tool(s) are missing on your host machine."
        Write-Muted "Osprey will gracefully adapt and use whichever tools are installed."
        
        $hasWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
        $hasGo = [bool](Get-Command go -ErrorAction SilentlyContinue)

        $attemptInstall = Read-Host "`nAttempt automatic installation of missing tools? [Y/n]"
        if ($attemptInstall -ne "n" -and $attemptInstall -ne "N") {
            if ($hasGo) {
                $goMap = @{
                    "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                    "httpx"     = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
                    "naabu"     = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
                    "dnsx"      = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
                    "tlsx"      = "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
                    "katana"    = "github.com/projectdiscovery/katana/cmd/katana@latest"
                    "nuclei"    = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                }
                foreach ($m in $missingTools) {
                    if ($goMap.ContainsKey($m.Name)) {
                        Write-Host "  Installing $($m.Name) via go install..." -ForegroundColor Cyan
                        try {
                            go install $goMap[$m.Name]
                            Write-Success "$($m.Name) installed successfully."
                        } catch {
                            Write-WarnItem "Failed to install $($m.Name): $_"
                        }
                    }
                }
            }

            if ($hasWinget -and ($missingTools | Where-Object { $_.Name -eq "nmap" })) {
                Write-Host "  Installing Nmap via winget..." -ForegroundColor Cyan
                try {
                    winget install --id Insecure.Nmap -e --silent --accept-source-agreements --accept-package-agreements
                    Write-Success "Nmap installation invoked."
                } catch {
                    Write-WarnItem "Winget install failed. Download Nmap manually: https://nmap.org/download.html"
                }
            }
        }
        Write-Host ""
        Write-Muted "Pro-tip: For Windows users wanting all 90+ tools pre-configured, Full Docker (Option 1)"
        Write-Muted "or running inside WSL2 (scripts/install.sh) is strongly recommended."
    }
}

# ==============================================================================
# [3/5] Usage Mode Selection
# ==============================================================================
Write-Header "[3/5] How do you plan to use Osprey?"

Write-Host "  1) Both Built-in CLI & AI Harness (MCP) (Recommended - complete access)" -ForegroundColor White
Write-Muted "Use our native CLI (osprey) AND connect AI clients like Claude, Cursor, OpenCode."

Write-Host "  2) Built-in CLI only" -ForegroundColor White
Write-Muted "Drive tests directly via the interactive terminal interface (osprey / python -m cli)."

Write-Host "  3) AI Harness via MCP only" -ForegroundColor White
Write-Muted "Control Osprey exclusively from Claude Desktop, Cursor, OpenCode, Windsurf, or ChatGPT."

$usageChoice = Read-Host "`nSelect usage mode [1]"
if (-not $usageChoice) { $usageChoice = "1" }

$needsCliLlm = ($usageChoice -eq "1" -or $usageChoice -eq "2")

# ==============================================================================
# [4/5] LLM Configuration
# ==============================================================================
Write-Header "[4/5] LLM Provider Configuration"

if ($needsCliLlm) {
    Write-Host "The Osprey CLI uses LiteLLM to drive its autonomous agent loop." -ForegroundColor White
    Write-Host "Select your LLM provider preset or enter a custom identifier:" -ForegroundColor Cyan
    Write-Host "  1) Anthropic    : anthropic/claude-sonnet-5"
    Write-Host "  2) OpenAI       : openai/gpt-4o"
    Write-Host "  3) Google Gemini: gemini/gemini-2.5-flash"
    Write-Host "  4) OpenRouter   : openrouter/anthropic/claude-sonnet-5"
    Write-Host "  5) Groq         : groq/llama-3.3-70b-versatile"
    Write-Host "  6) Local Ollama : ollama/llama3.3"
    Write-Host "  7) Custom model identifier"
    Write-Host "  0) Skip (configure in .env manually later)"

    $preset = Read-Host "`nChoose provider preset [1]"
    if (-not $preset) { $preset = "1" }

    $chosenModel = ""
    switch ($preset) {
        "1" { $chosenModel = "anthropic/claude-sonnet-5" }
        "2" { $chosenModel = "openai/gpt-4o" }
        "3" { $chosenModel = "gemini/gemini-2.5-flash" }
        "4" { $chosenModel = "openrouter/anthropic/claude-sonnet-5" }
        "5" { $chosenModel = "groq/llama-3.3-70b-versatile" }
        "6" { $chosenModel = "ollama/llama3.3" }
        "7" {
            $chosenModel = Read-Host "Enter LiteLLM model identifier (e.g. openai/gpt-4o)"
        }
        "0" {
            Write-WarnItem "Skipped LLM configuration. Please configure LLM_MODEL in .env before running CLI."
        }
    }

    if ($chosenModel) {
        Set-EnvVar -Key "LLM_MODEL" -Value $chosenModel
        Write-Success "Saved LLM_MODEL=$chosenModel"

        if (-not ($chosenModel -like "ollama/*")) {
            $plainKey = ""
            if ([System.Console]::IsInputRedirected) {
                $plainKey = Read-Host "Enter API key for $chosenModel [Enter to skip]"
            } else {
                try {
                    $secureKey = Read-Host "Enter API key for $chosenModel [Enter to skip]" -AsSecureString
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
                    $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                } catch {
                    $plainKey = Read-Host "Enter API key for $chosenModel [Enter to skip]"
                }
            }
            if ($plainKey) {
                Set-EnvVar -Key "LLM_API_KEY" -Value $plainKey
                Write-Success "Saved LLM_API_KEY to .env"
            } else {
                Write-WarnItem "Key skipped. Remember to populate LLM_API_KEY in .env."
            }
        }
    }
} else {
    Write-Host "In MCP mode, your AI harness (Claude, Cursor, OpenCode, etc.) supplies its own LLM." -ForegroundColor Green
    Write-Host "Osprey CLI agent config is not required for MCP operation." -ForegroundColor DarkGray
}

# ==============================================================================
# [5/5] Optional OSINT API Keys & MCP Harness Auto-Configuration
# ==============================================================================
Write-Header "[5/5] Optional OSINT API Keys & MCP Integration"

$optKeys = Read-Host "Configure optional OSINT API keys (Shodan, IntelX)? [y/N]"
if ($optKeys -eq "y" -or $optKeys -eq "Y") {
    $shodanKey = Read-Host "Shodan API Key [Enter to skip]"
    if ($shodanKey) { Set-EnvVar -Key "SHODAN_API_KEY" -Value $shodanKey; Write-Success "Saved SHODAN_API_KEY" }

    $intelxKey = Read-Host "IntelX API Key [Enter to skip]"
    if ($intelxKey) { Set-EnvVar -Key "INTELX_API_KEY" -Value $intelxKey; Write-Success "Saved INTELX_API_KEY" }
}

# ── Generate standalone mcp-config.json ───────────────────────────────────────
$pythonExe = Resolve-PythonPath
$serverScript = "$RootDir\platform-mcp\server.py"
$batScript = "$RootDir\scripts\run-mcp-pentest.bat"

# Obtain 8.3 short paths if available to prevent space-splitting bugs across Windows IDEs
$shortRoot = $RootDir
$shortBat = $batScript
$shortPython = $pythonExe
$shortServer = $serverScript

try {
    $fso = New-Object -ComObject Scripting.FileSystemObject
    if (Test-Path $RootDir) { $shortRoot = $fso.GetFolder($RootDir).ShortPath }
    if (Test-Path $batScript) { $shortBat = $fso.GetFile($batScript).ShortPath }
    if (Test-Path $pythonExe) { $shortPython = $fso.GetFile($pythonExe).ShortPath }
    if (Test-Path $serverScript) { $shortServer = $fso.GetFile($serverScript).ShortPath }
} catch {}

$mcpConfigContent = @{
    "claude_desktop" = @{
        "mcpServers" = @{
            "osprey" = @{
                "command" = $shortPython
                "args"    = @($shortServer)
                "cwd"     = $shortRoot
                "env"     = @{
                    "PENTEST_API_BASE"      = "http://localhost:9000"
                    "PENTEST_QUICK_TIMEOUT" = "60"
                    "PENTEST_HTTP_TIMEOUT"  = "900"
                }
            }
        }
    }
    "cursor" = @{
        "mcpServers" = @{
            "osprey" = @{
                "command" = "cmd.exe"
                "args"    = @("/c", $shortBat)
                "env"     = @{
                    "PENTEST_API_BASE"      = "http://localhost:9000"
                    "PENTEST_QUICK_TIMEOUT" = "60"
                    "PENTEST_HTTP_TIMEOUT"  = "900"
                }
            }
        }
    }
    "opencode" = @{
        "mcp" = @{
            "osprey" = @{
                "type"        = "local"
                "command"     = @($shortBat)
                "cwd"         = $shortRoot
                "environment" = @{
                    "PENTEST_API_BASE"      = "http://localhost:9000"
                    "PENTEST_QUICK_TIMEOUT" = "60"
                }
                "enabled"     = $true
                "timeout"     = 960000
            }
        }
    }
}

$mcpJsonStr = $mcpConfigContent | ConvertTo-Json -Depth 10
Set-Content -Path "$RootDir\mcp-config.json" -Value $mcpJsonStr -Encoding utf8
Write-Success "Generated reference MCP config: mcp-config.json"

# ── Check and configure detected harnesses ───────────────────────────────────
Write-Host "`nScanning for installed AI harnesses on your system..." -ForegroundColor Cyan

$detectedHarnesses = @()

# 1. Claude Desktop
$claudeConfig = "$env:APPDATA\Claude\claude_desktop_config.json"
if (Test-Path (Split-Path $claudeConfig -Parent)) {
    $detectedHarnesses += @{ Name = "Claude Desktop"; Path = $claudeConfig; Type = "claude" }
}

# 2. Cursor
$cursorDir = "$env:USERPROFILE\.cursor"
if (Test-Path $cursorDir) {
    $detectedHarnesses += @{ Name = "Cursor (Global)"; Path = "$cursorDir\mcp.json"; Type = "cursor" }
}
$detectedHarnesses += @{ Name = "Cursor (Workspace .cursor/mcp.json)"; Path = "$RootDir\.cursor\mcp.json"; Type = "cursor" }

# 3. OpenCode
$opencodeDir = "$env:USERPROFILE\.config\opencode"
if (Test-Path $opencodeDir) {
    $opencodeFile = if (Test-Path "$opencodeDir\opencode.jsonc") { "$opencodeDir\opencode.jsonc" } else { "$opencodeDir\opencode.json" }
    $detectedHarnesses += @{ Name = "OpenCode"; Path = $opencodeFile; Type = "opencode" }
    # Remove conflicting opencode.json if opencode.jsonc exists
    if ((Test-Path "$opencodeDir\opencode.jsonc") -and (Test-Path "$opencodeDir\opencode.json")) {
        Remove-Item "$opencodeDir\opencode.json" -Force -ErrorAction SilentlyContinue
    }
}

# 4. Windsurf
$windsurfDir = "$env:USERPROFILE\.codeium\windsurf"
if (Test-Path $windsurfDir) {
    $detectedHarnesses += @{ Name = "Windsurf"; Path = "$windsurfDir\mcp_config.json"; Type = "cursor" }
}

if ($detectedHarnesses.Count -gt 0) {
    Write-Host "Found detected AI harnesses:" -ForegroundColor Green
    foreach ($h in $detectedHarnesses) {
        Write-Host "  - $($h.Name) at $($h.Path)" -ForegroundColor White
    }

    $autoConfig = Read-Host "`nAutomatically configure Osprey MCP in detected harnesses? [Y/n]"
    if ($autoConfig -ne "n" -and $autoConfig -ne "N") {
        foreach ($h in $detectedHarnesses) {
            $cfgPath = $h.Path
            $cfgDir = Split-Path $cfgPath -Parent
            if (-not (Test-Path $cfgDir)) {
                New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
            }

            # Backup if exists
            if (Test-Path $cfgPath) {
                $bak = "$cfgPath.bak_" + (Get-Date -Format "yyyyMMddHHmmss")
                Copy-Item $cfgPath $bak -Force
                Write-Muted "Created backup: $bak"
            }

            try {
                $jsonObj = @{}
                if (Test-Path $cfgPath) {
                    $raw = Get-Content $cfgPath -Raw -ErrorAction SilentlyContinue
                    # Strip comments for simple json parsing
                    if ($raw) {
                        $clean = $raw -replace "(?m)^\s*//.*$", ""
                        $parsed = $clean | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($parsed) {
                            # Convert PSObject to hashtable
                            foreach ($prop in $parsed.PSObject.Properties) {
                                $jsonObj[$prop.Name] = $prop.Value
                            }
                        }
                    }
                }

                if ($h.Type -eq "opencode") {
                    if (-not $jsonObj.ContainsKey("mcp")) { $jsonObj["mcp"] = @{} }
                    $jsonObj["mcp"]["osprey"] = $mcpConfigContent["opencode"]["mcp"]["osprey"]
                } elseif ($h.Type -eq "cursor") {
                    if (-not $jsonObj.ContainsKey("mcpServers")) { $jsonObj["mcpServers"] = @{} }
                    $jsonObj["mcpServers"]["osprey"] = $mcpConfigContent["cursor"]["mcpServers"]["osprey"]
                } else {
                    if (-not $jsonObj.ContainsKey("mcpServers")) { $jsonObj["mcpServers"] = @{} }
                    $jsonObj["mcpServers"]["osprey"] = $mcpConfigContent["claude_desktop"]["mcpServers"]["osprey"]
                }

                $outStr = $jsonObj | ConvertTo-Json -Depth 10
                Set-Content -Path $cfgPath -Value $outStr -Encoding utf8
                Write-Success "Configured Osprey MCP in $($h.Name)"
            } catch {
                Write-WarnItem "Could not automatically write $($h.Name): $_. See mcp-config.json for manual config."
            }
        }
    }
} else {
    Write-Host "No pre-existing harness config directories detected automatically." -ForegroundColor DarkGray
    Write-Host "Reference mcp-config.json was created for quick manual setup." -ForegroundColor DarkGray
}

# ==============================================================================
# Setup Complete - Summary & Next Steps
# ==============================================================================
Write-Header "Setup Complete! Next Steps"

if ($runtimeChoice -in @("1", "2")) {
    Write-Host "  * Backend Status: Running inside Docker at http://localhost:9000" -ForegroundColor Green
    Write-Host "    Inspect logs anytime : docker compose logs -f backend" -ForegroundColor DarkGray
} elseif ($runtimeChoice -in @("3", "4")) {
    Write-Host "  * Backend Status: Configured for local execution" -ForegroundColor Yellow
    Write-Host "    Start backend       : .\.venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "                          uvicorn osprey.main:app --host 0.0.0.0 --port 9000" -ForegroundColor White
}

if ($needsCliLlm) {
    Write-Host "`n  * Running the Osprey CLI:" -ForegroundColor Cyan
    Write-Host "    .\.venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "    osprey                          # Interactive Commander CLI" -ForegroundColor White
    Write-Host "    osprey scan example.com         # Direct scan entry point" -ForegroundColor White
}

Write-Host "`n  * AI Harness (MCP):" -ForegroundColor Cyan
Write-Host "    Osprey MCP is ready to be launched via:" -ForegroundColor White
Write-Host "    $pythonExe $serverScript" -ForegroundColor DarkGray
Write-Host "    See mcp-config.json for copy-pasteable JSON configs." -ForegroundColor DarkGray

Write-Host "`nHappy hunting!`n" -ForegroundColor Green
