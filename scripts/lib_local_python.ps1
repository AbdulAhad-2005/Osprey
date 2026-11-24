# Shared by install.ps1 and setup.ps1 - not standalone, dot-source after
# $RootDir is set: . (Join-Path $PSScriptRoot "lib_local_python.ps1")
#
# PowerShell port of lib_local_python.sh - see that file for the full
# rationale. Resolves a Python interpreter to create the local .venv with,
# transparently matching whatever Python version a downstream build's
# precompiled PyArmor runtime needs (e.g. Ababeel) - regardless of what
# `python`/`python3`/`py` already resolves to on this machine, and without
# the user needing to know or care what their Python version is. A
# plain-source checkout (Osprey) has no pyarmor_runtime_* marker at the repo
# root, so this is a complete no-op there.
$script:PyarmorTargetPython = "3.12"

function Test-PyarmorMarkerPresent {
    [bool](Get-ChildItem -Path $RootDir -Filter "pyarmor_runtime_*" -Directory -ErrorAction SilentlyContinue)
}

function Test-PythonReportsVersion {
    param([string]$Exe, [string]$Wanted)
    try { $out = & $Exe -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { return $false }
    return ($out -eq $Wanted)
}

function Find-SystemPython {
    foreach ($cand in @("python.exe", "python3.exe", "py.exe")) {
        $c = Get-Command $cand -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    return $null
}

# Prints the chosen interpreter's path, or $null if none could be found or
# provisioned.
function Resolve-LocalVenvPython {
    if (-not (Test-PyarmorMarkerPresent)) {
        $found = Find-SystemPython
        if ($found) { return $found }
        Write-Host "  [!] Python not found. Install Python 3.12+, then re-run." -ForegroundColor Yellow
        return $null
    }

    foreach ($cand in @("python.exe", "python3.exe", "py.exe")) {
        $c = Get-Command $cand -ErrorAction SilentlyContinue
        if ($c -and (Test-PythonReportsVersion $c.Source $script:PyarmorTargetPython)) {
            return $c.Source
        }
    }

    $hostPy = Find-SystemPython
    $hminor = "?"
    if ($hostPy) {
        try { $hminor = & $hostPy -c "import sys; print(sys.version_info.minor)" 2>$null } catch { }
    }
    Write-Host "  [!] This build's precompiled runtime needs Python $($script:PyarmorTargetPython) specifically" -ForegroundColor Yellow
    Write-Host "      (this machine's python is 3.$hminor) - fetching an isolated one with 'uv'," -ForegroundColor Yellow
    Write-Host "      which touches nothing system-wide and needs no admin rights." -ForegroundColor Yellow

    $uv = Get-Command uv.exe -ErrorAction SilentlyContinue
    if (-not $uv) {
        $ans = Read-Host "      Install uv now to get Python $($script:PyarmorTargetPython)? [Y/n]"
        if ($ans -and $ans -notmatch '^[Yy]') { return $null }
        try {
            $script = (Invoke-WebRequest -Uri "https://astral.sh/uv/install.ps1" -UseBasicParsing).Content
            Invoke-Expression $script
        } catch { }
        $env:PATH = "$env:PATH;$HOME\.local\bin"
        $uv = Get-Command uv.exe -ErrorAction SilentlyContinue
    }
    if (-not $uv) {
        Write-Host "      Could not install uv automatically. Install Python $($script:PyarmorTargetPython) yourself" -ForegroundColor Yellow
        Write-Host "      (e.g. 'uv python install $($script:PyarmorTargetPython)' once uv is on PATH, or from" -ForegroundColor Yellow
        Write-Host "      python.org), then re-run this wizard." -ForegroundColor Yellow
        return $null
    }

    $found = (& $uv.Source python find $script:PyarmorTargetPython 2>$null)
    if ($found) { $found = $found.Trim() }
    if (-not $found) {
        Write-Host "      Fetching Python $($script:PyarmorTargetPython) via uv (one-time download) ..." -ForegroundColor Cyan
        & $uv.Source python install $script:PyarmorTargetPython 2>&1 | Out-Null
        $found = (& $uv.Source python find $script:PyarmorTargetPython 2>$null)
        if ($found) { $found = $found.Trim() }
    }
    if ($found -and (Test-PythonReportsVersion $found $script:PyarmorTargetPython)) {
        return $found
    }
    Write-Host "      Still couldn't get Python $($script:PyarmorTargetPython) working via uv. Install it yourself," -ForegroundColor Yellow
    Write-Host "      then re-run this wizard." -ForegroundColor Yellow
    return $null
}

# True if an EXISTING venv's own python is wrong for this build (needs
# recreating), independent of whether it was just created or already existed.
function Test-LocalVenvPythonIsWrong {
    param([string]$PyPath)
    if (-not $PyPath -or -not (Test-Path $PyPath)) { return $false }
    if (-not (Test-PyarmorMarkerPresent)) { return $false }
    return -not (Test-PythonReportsVersion $PyPath $script:PyarmorTargetPython)
}
