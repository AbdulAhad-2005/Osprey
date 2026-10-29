# ==============================================================================
# Osprey - Guided Interactive Setup & Onboarding Wizard (Windows PowerShell)
# ==============================================================================
#
# Walks through:
#   [1/5] Tool execution & infrastructure mode (Full Docker / Lean Docker / Fully Local)
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

$Brand = if ($env:OSPREY_APP_NAME) { $env:OSPREY_APP_NAME } else { "Osprey" }

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
    $bPort = Get-EnvVar "BACKEND_PORT" "9000"
    $bUrl = Get-EnvVar "API_BASE_URL" "http://localhost:$bPort"
    $healthUrl = "$bUrl/health"
    Write-Host -NoNewline "  Waiting for backend at $healthUrl " -ForegroundColor Cyan
    for ($i = 0; $i -lt $MaxSeconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($r.StatusCode -eq 200) {
                Write-Host ""
                Write-Success "Backend is healthy and listening on $bUrl"
                return $true
            }
        } catch { }
        Write-Host -NoNewline "." -ForegroundColor DarkGray
        Start-Sleep -Seconds 1
    }
    Write-Host ""
    Write-WarnItem "Backend did not respond within $MaxSeconds seconds. It may still be starting."
    # Most common first-run failure: an existing Postgres volume was created with a
    # different password than DATABASE_URL now uses (e.g. an old .env with the
    # <db-password> placeholder). The volume's password can't be changed by env
    # vars — the volume must be reset.
    $logs = ""
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        try { $logs = & docker compose logs backend 2>$null | Out-String } catch { }
    }
    if ($logs -match "password authentication failed|PasswordError|OperationalError.*password") {
        Write-FailItem "Database password mismatch: the Postgres volume was created with a different password."
        Write-Muted "Reset the database volume (this DELETES local DB data) and re-run the wizard:"
        Write-Muted "    docker compose down -v ; powershell -ExecutionPolicy Bypass -File scripts\install.ps1"
    } elseif ($logs -match "could not connect to server|connection refused|could not translate host name|OperationalError") {
        # A stale .env from an earlier manual edit (wrong host/port in
        # DATABASE_URL) is the other common cause — this wizard always writes a
        # consistent DATABASE_URL for Docker modes.
        Write-FailItem "The backend can't reach Postgres - DATABASE_URL in .env looks stale or wrong."
        Write-Muted "Fix: let the wizard rewrite it - re-run install.ps1 and pick option 1 or 2 again"
        Write-Muted "(it always sets a consistent, working DATABASE_URL)."
    } else {
        Write-WarnItem "Inspect logs using:  docker compose logs -f backend"
    }
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

# The Osprey MCP server is a small local stdio bridge to the backend's HTTP API —
# it needs its own Python deps (mcp, httpx) regardless of how the backend runs.
# In Docker-only setups no .venv is ever created, so the MCP config would point at
# a system Python without those deps and the harness launch dies with
# "ModuleNotFoundError: No module named 'httpx'". Ensure a .venv that HAS the deps.
$mcpDepsOk = $true
function Resolve-McpPython {
    $py = "$RootDir\.venv\Scripts\python.exe"
    if (Test-Path $py) {
        & $py -c "import httpx, mcp" 2>$null
        if ($LASTEXITCODE -eq 0) { return }   # already usable
    }
    Write-Step "Preparing a local Python environment for the $($Brand) MCP bridge..."
    if (-not (Test-Path $py)) {
        $sys = $null
        foreach ($cand in @("python.exe", "python3.exe", "py.exe")) {
            $c = Get-Command $cand -ErrorAction SilentlyContinue
            if ($c) { $sys = $c.Source; break }
        }
        if (-not $sys) { Write-WarnItem "Python not found - cannot prepare the MCP environment. Install Python 3, then re-run."; $script:mcpDepsOk = $false; return }
        & $sys -m venv "$RootDir\.venv"
        if (-not (Test-Path $py)) { Write-WarnItem "Could not create .venv; MCP may fail to launch."; $script:mcpDepsOk = $false; return }
    }
    & $py -m pip install --upgrade pip --quiet 2>$null | Out-Null
    & $py -m pip install --quiet -r "$RootDir\platform-mcp\requirements.txt"
    if ($LASTEXITCODE -eq 0) {
        Write-Success "MCP bridge dependencies installed into .venv (mcp, httpx)."
    } else {
        Write-WarnItem "Failed to install MCP deps into .venv; the harness launch may fail."
        $script:mcpDepsOk = $false
    }
}

$cliDepsOk = $true
$guiDepsOk = $true

function Ensure-CliPython {
    $py = "$RootDir\.venv\Scripts\python.exe"
    if (-not (Test-Path $py)) {
        $sys = $null
        foreach ($cand in @("python.exe", "python3.exe", "py.exe")) {
            $c = Get-Command $cand -ErrorAction SilentlyContinue
            if ($c) { $sys = $c.Source; break }
        }
        if (-not $sys) {
            Write-WarnItem "Python 3.12+ not found - cannot install the $($Brand) CLI."
            $script:cliDepsOk = $false
            return
        }
        Write-Step "Preparing a local Python environment for the $($Brand) CLI..."
        & $sys -m venv "$RootDir\.venv"
        if (-not (Test-Path $py)) {
            Write-WarnItem "Could not create .venv; the CLI is not installed."
            $script:cliDepsOk = $false
            return
        }
    }
    & $py -m pip install --upgrade pip --quiet 2>$null | Out-Null
    & $py -m pip install --quiet -e "$RootDir\agent_core" -e "$RootDir\cli"
    if ($LASTEXITCODE -eq 0) {
        Write-Success "$($Brand) CLI installed into .venv (osprey command ready after activation)."
    } else {
        Write-WarnItem "Failed to install the $($Brand) CLI. Retry: $py -m pip install -e .\agent_core -e .\cli"
        $script:cliDepsOk = $false
    }
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

Write-Host "Welcome to the $($Brand) setup wizard. Press Ctrl+C anytime to exit." -ForegroundColor DarkGray
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
Write-Header "[1/5] How should $($Brand) & security tools run?"

Write-Host "  1) Full Docker (Recommended)" -ForegroundColor White
Write-Muted "All-in-one: Postgres DB, Backend API & 90+ Kali tools in Docker."
Write-Muted "Zero tool installation required on your host system."

Write-Host "  2) Lean Docker (Custom Tools Container)" -ForegroundColor White
Write-Muted "Postgres & Backend in Docker; tools executed via your own existing container."

Write-Host "  3) Fully Local, No Docker (Self-contained / SQLite)" -ForegroundColor White
Write-Muted "Backend and tools run on this machine with a local SQLite database - no Docker, no Postgres."

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
        # Keep the Postgres password and DATABASE_URL password in lock-step so a
        # stale .env (still carrying the <db-password> placeholder) can't make the
        # DB init with one password and the backend connect with another (503).
        Set-EnvVar -Key "POSTGRES_PASSWORD" -Value "pentest"
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
        Set-EnvVar -Key "POSTGRES_PASSWORD" -Value "pentest"
        Set-EnvVar -Key "DATABASE_URL" -Value "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

        Write-Step "Starting Postgres + Backend in Docker (targeting container $toolsCont)..."
        docker compose up -d
        if ($LASTEXITCODE -ne 0) { Write-FailItem "docker compose failed."; exit 1 }
        Write-Success "Stack started. Tools will be executed into container: $toolsCont"
        Wait-ForBackend | Out-Null
    }

    "3" {
        Set-EnvVar -Key "DATABASE_URL" -Value "sqlite:///./pentest.db"
        Set-EnvVar -Key "KALI_CONTAINER" -Value ""

        Write-Step "Configured SQLite local database (pentest.db) - nothing else to connect."
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
# [2/5] Tool Environment Detection (For the Fully Local mode)
# ==============================================================================
if ($runtimeChoice -eq "3") {
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
        Write-Muted "$($Brand) will gracefully adapt and use whichever tools are installed."
        
        $hasWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
        $hasGo = [bool](Get-Command go -ErrorAction SilentlyContinue)

        $attemptInstall = Read-Host "`nAttempt automatic installation of missing tools? [Y/n]"
        if ($attemptInstall -ne "n" -and $attemptInstall -ne "N") {
            $goToolsMissing = @("subfinder", "httpx", "naabu", "dnsx", "tlsx", "katana", "nuclei")
            if (($missingTools.Name | Where-Object { $_ -in $goToolsMissing }) -and -not $hasGo) {
                if ($hasWinget) {
                    Write-Host "  Installing Go, required for ProjectDiscovery tools..." -ForegroundColor Cyan
                    winget install --id GoLang.Go -e --silent --accept-source-agreements --accept-package-agreements
                    if ($LASTEXITCODE -eq 0) {
                        Write-WarnItem "Go installation completed. Restart PowerShell and re-run the wizard to install ProjectDiscovery tools."
                    } else {
                        Write-WarnItem "Could not install Go; ProjectDiscovery tools were not installed."
                    }
                } else {
                    Write-WarnItem "Go is not installed and winget is unavailable; ProjectDiscovery tools were not installed."
                }
            }

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
                        & go install $goMap[$m.Name]
                        if ($LASTEXITCODE -eq 0) {
                            $goBin = (& go env GOBIN 2>$null)
                            if (-not $goBin) { $goBin = Join-Path (& go env GOPATH 2>$null) "bin" }
                            $goBin = $goBin.Trim()
                            if (Test-Path (Join-Path $goBin "$($m.Name).exe")) {
                                $env:Path = "$goBin;$env:Path"
                                $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
                                $userPathParts = @()
                                if ($userPath) { $userPathParts = $userPath -split ";" | Where-Object { $_ } }
                                if ($userPathParts -notcontains $goBin) {
                                    $newUserPath = (($userPathParts + $goBin) -join ";")
                                    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
                                    Write-Muted "Added $goBin to your user PATH for future shells."
                                }
                            }
                            if (Get-Command $m.Name -ErrorAction SilentlyContinue) {
                                Write-Success "$($m.Name) installed and available on PATH."
                            } else {
                                Write-WarnItem "$($m.Name) was downloaded, but its Go bin directory is not available in this shell."
                                Write-Muted "Open a new PowerShell (or add $goBin to PATH) and re-run the tool check."
                            }
                        } else {
                            Write-WarnItem "go install $($m.Name) failed; it was not installed."
                        }
                    }
                }
            }
            if (-not $hasGo -and -not $hasWinget) {
                Write-WarnItem "No supported installer was available for the missing tools."
            }

            if ($hasWinget -and ($missingTools | Where-Object { $_.Name -eq "nmap" })) {
                Write-Host "  Installing Nmap via winget..." -ForegroundColor Cyan
                winget install --id Insecure.Nmap -e --silent --accept-source-agreements --accept-package-agreements
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Nmap installation invoked."
                } else {
                    Write-WarnItem "Winget install failed. Download Nmap manually: https://nmap.org/download.html"
                }
            }

            $remainingTools = @($missingTools | Where-Object {
                -not (Get-Command $_.Cmd -ErrorAction SilentlyContinue)
            })
            if ($remainingTools.Count -eq 0) {
                Write-Success "All requested host tools are now available on PATH."
            } else {
                Write-WarnItem "Still unavailable after installation attempt: $($remainingTools.Name -join ', ')"
                Write-Muted "Re-run the wizard after fixing the package manager, Go, or PATH."
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
Write-Header "[3/5] How do you plan to use $($Brand)?"

Write-Host "  1) Both Built-in CLI & AI Harness (MCP) (Recommended - complete access)" -ForegroundColor White
Write-Muted "Use our native CLI (osprey) AND connect AI clients like Claude, Cursor, OpenCode."

Write-Host "  2) Built-in CLI only" -ForegroundColor White
Write-Muted "Drive tests directly via the interactive terminal interface (osprey / python -m cli)."

Write-Host "  3) AI Harness via MCP only" -ForegroundColor White
Write-Muted "Control $($Brand) exclusively from Claude Desktop, Cursor, OpenCode, Windsurf, or ChatGPT."

Write-Host "  4) Operator Console GUI only" -ForegroundColor White
Write-Muted "Use the web dashboard at http://localhost:3100 (requires Node.js 18.18+)."

$usageChoice = Read-Host "`nSelect usage mode [1]"
if (-not $usageChoice) { $usageChoice = "1" }
if ($usageChoice -notin @("1", "2", "3", "4")) {
    Write-FailItem "Unrecognized option: $usageChoice"
    exit 1
}

$needsCliLlm = ($usageChoice -eq "1" -or $usageChoice -eq "2")
$wantsGui = $usageChoice -eq "4"

# ==============================================================================
# [4/5] LLM Configuration
# ==============================================================================
Write-Header "[4/5] LLM Provider Configuration"

if ($needsCliLlm) {
    Write-Host "The $($Brand) CLI uses LiteLLM to drive its autonomous agent loop." -ForegroundColor White
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
    Write-Host "$($Brand) CLI agent config is not required for MCP operation." -ForegroundColor DarkGray
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

# ── Install selected local interfaces and generate standalone mcp-config.json ─
if ($needsCliLlm) {
    Ensure-CliPython
} elseif ($usageChoice -eq "3") {
    Resolve-McpPython
}

if ($wantsGui) {
    $node = Get-Command node -ErrorAction SilentlyContinue
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    $nodeVersion = if ($node) { (& node -p "process.versions.node" 2>$null) } else { "" }
    $nodeParts = if ($nodeVersion) { $nodeVersion.Trim().Split(".") } else { @() }
    $nodeSupported = $nodeParts.Count -ge 2 -and
        (([int]$nodeParts[0] -gt 18) -or
         (([int]$nodeParts[0] -eq 18) -and ([int]$nodeParts[1] -ge 18)))
    if ($node -and $npm -and $nodeSupported) {
        Write-Step "Installing Operator Console dependencies..."
        Push-Location "$RootDir\gui"
        try { & npm install } finally { Pop-Location }
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Operator Console dependencies installed."
        } else {
            Write-WarnItem "GUI dependency installation failed. Retry with: cd gui; npm install"
            $guiDepsOk = $false
        }
    } else {
        Write-WarnItem "Node.js/npm is missing or Node.js $nodeVersion is too old. Install Node.js 18.18+, then run: cd gui; npm install"
        $guiDepsOk = $false
    }
}

# Make sure the interpreter we hand the harness actually has the MCP deps.
$pythonExe = Resolve-PythonPath
$serverScript = "$RootDir\platform-mcp\server.py"
$batScript = "$RootDir\scripts\run-mcp-pentest.bat"

# White-label hook (default "osprey" is a no-op): a downstream build sets
# $env:OSPREY_MCP_SERVER_NAME to rebrand the generated/auto-written MCP
# config key name -- matches platform-mcp/server.py's own FastMCP(...) name.
$McpServerName = if ($env:OSPREY_MCP_SERVER_NAME) { $env:OSPREY_MCP_SERVER_NAME } else { "osprey" }

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

$cfgPort = Get-EnvVar "BACKEND_PORT" "9000"
$mcpApiBase = Get-EnvVar "API_BASE_URL" "http://localhost:$cfgPort"

$mcpConfigContent = @{
    "claude_desktop" = @{
        "mcpServers" = @{
            "$McpServerName" = @{
                "command" = $shortPython
                "args"    = @($shortServer)
                "cwd"     = $shortRoot
                "env"     = @{
                    "OSPREY_MCP_SERVER_NAME"       = $McpServerName
                    "PENTEST_API_BASE"      = $mcpApiBase
                    "PENTEST_QUICK_TIMEOUT" = "60"
                    "PENTEST_HTTP_TIMEOUT"  = "900"
                }
            }
        }
    }
    "cursor" = @{
        "mcpServers" = @{
            "$McpServerName" = @{
                "command" = "cmd.exe"
                "args"    = @("/c", $shortBat)
                "env"     = @{
                    "OSPREY_MCP_SERVER_NAME"       = $McpServerName
                    "PENTEST_API_BASE"      = $mcpApiBase
                    "PENTEST_QUICK_TIMEOUT" = "60"
                    "PENTEST_HTTP_TIMEOUT"  = "900"
                }
            }
        }
    }
    "opencode" = @{
        "mcp" = @{
            "$McpServerName" = @{
                "type"        = "local"
                "command"     = @($shortBat)
                "cwd"         = $shortRoot
                "environment" = @{
                    "OSPREY_MCP_SERVER_NAME"       = $McpServerName
                    "PENTEST_API_BASE"      = $mcpApiBase
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
if ($usageChoice -eq "1" -or $usageChoice -eq "3") {
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

    $autoConfig = Read-Host "`nAutomatically configure $($Brand) MCP in detected harnesses? [Y/n]"
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
                    $jsonObj["mcp"][$McpServerName] = $mcpConfigContent["opencode"]["mcp"][$McpServerName]
                } elseif ($h.Type -eq "cursor") {
                    if (-not $jsonObj.ContainsKey("mcpServers")) { $jsonObj["mcpServers"] = @{} }
                    $jsonObj["mcpServers"][$McpServerName] = $mcpConfigContent["cursor"]["mcpServers"][$McpServerName]
                } else {
                    if (-not $jsonObj.ContainsKey("mcpServers")) { $jsonObj["mcpServers"] = @{} }
                    $jsonObj["mcpServers"][$McpServerName] = $mcpConfigContent["claude_desktop"]["mcpServers"][$McpServerName]
                }

                $outStr = $jsonObj | ConvertTo-Json -Depth 10
                Set-Content -Path $cfgPath -Value $outStr -Encoding utf8
                Write-Success "Configured $($Brand) MCP in $($h.Name)"
            } catch {
                Write-WarnItem "Could not automatically write $($h.Name): $_. See mcp-config.json for manual config."
            }
        }
    }
} else {
    Write-Host "No pre-existing harness config directories detected automatically." -ForegroundColor DarkGray
    Write-Host "Reference mcp-config.json was created for quick manual setup." -ForegroundColor DarkGray
}
} else {
    Write-Host "Skipped AI harness auto-configuration (MCP was not selected)." -ForegroundColor DarkGray
}

# ==============================================================================
# Setup Complete - Summary & Next Steps
# ==============================================================================
Write-Header "Setup Complete! Next Steps"

if ($runtimeChoice -in @("1", "2")) {
    $statPort = Get-EnvVar "BACKEND_PORT" "9000"
    $statUrl = Get-EnvVar "API_BASE_URL" "http://localhost:$statPort"
    Write-Host "  * Backend Status: Running inside Docker at $statUrl" -ForegroundColor Green
    Write-Host "    Inspect logs anytime : docker compose logs -f backend" -ForegroundColor DarkGray
    Write-Host "    Stop it              : docker compose down" -ForegroundColor DarkGray
} elseif ($runtimeChoice -eq "3") {
    Write-Host "  * Backend Status: Configured for local execution (not started yet)" -ForegroundColor Yellow
    Write-Host "    Start it now        : powershell -ExecutionPolicy Bypass -File scripts\serve.ps1" -ForegroundColor White
    Write-Host "    (leave that running; open a new terminal for the CLI/GUI)" -ForegroundColor DarkGray
}

if ($needsCliLlm) {
    Write-Host "`n  * Running the $($Brand) CLI:" -ForegroundColor Cyan
    if ($cliDepsOk) {
        Write-Host "    .\.venv\Scripts\Activate.ps1  # optional; makes the 'osprey' command available" -ForegroundColor White
        Write-Host "    osprey                          # Interactive Commander CLI" -ForegroundColor White
        Write-Host "    osprey scan example.com         # Direct scan entry point" -ForegroundColor White
        Write-Host "    Or run directly: $pythonExe -m cli" -ForegroundColor DarkGray
    } else {
        Write-Host "    CLI installation did NOT complete - the 'osprey' command is not ready." -ForegroundColor Red
    }
}

if ($usageChoice -eq "1" -or $usageChoice -eq "3") {
    Write-Host "`n  * AI Harness (MCP):" -ForegroundColor Cyan
    if ($mcpDepsOk) {
        Write-Host "    $($Brand) MCP is ready to be launched via:" -ForegroundColor White
        Write-Host "    $pythonExe $serverScript" -ForegroundColor DarkGray
        Write-Host "    See mcp-config.json for copy-pasteable JSON configs." -ForegroundColor DarkGray
    } else {
        Write-Host "    MCP dependencies did NOT install - the harness cannot launch $($Brand) yet." -ForegroundColor Red
    }
}

if ($wantsGui) {
    Write-Host "`n  * Operator Console GUI:" -ForegroundColor Cyan
    if ($guiDepsOk) {
        Write-Host "    cd gui; npm run dev             # http://localhost:3100" -ForegroundColor White
    } else {
        Write-Host "    GUI dependencies did NOT install. Install Node.js 18.18+ and run: cd gui; npm install" -ForegroundColor Red
    }
}

Write-Host "`nHappy hunting!`n" -ForegroundColor Green
