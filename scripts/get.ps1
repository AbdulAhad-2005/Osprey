# Osprey one-line bootstrap installer (Windows PowerShell).
#
#   powershell -c "irm https://raw.githubusercontent.com/AbdulAhad-2005/osprey/main/scripts/get.ps1 | iex"
#
# This script has NO repo checked out yet (that's the whole point) — it clones
# (or downloads) one, then hands off to the real interactive wizard,
# scripts\install.ps1, which is kept in one place and does the actual work.
#
# Env overrides: $env:OSPREY_DIR (clone target, default .\osprey), $env:OSPREY_REF
# (branch/tag, default main).
$ErrorActionPreference = "Stop"

$RepoOwner = "AbdulAhad-2005"
$RepoName = "osprey"
$RepoUrl = "https://github.com/$RepoOwner/$RepoName.git"
$Ref = if ($env:OSPREY_REF) { $env:OSPREY_REF } else { "main" }
$Dir = if ($env:OSPREY_DIR) { $env:OSPREY_DIR } else { "osprey" }

Write-Host @"
   ____  _____ _____  _____  ________   __
  / __ \/ ___// __ \/ __ \/ ____/\ \ / /
 / / / /\__ \/ /_/ / /_/ / __/    \ V /
/ /_/ /___/ / ____/ _, _/ /___     / /
\____//____/_/   /_/ |_/_____/    /_/
"@ -ForegroundColor Red

if ((Test-Path "./scripts/install.ps1") -and (Test-Path "./docker-compose.yml")) {
    Write-Host "==> Already inside an Osprey checkout — skipping clone." -ForegroundColor Cyan
    $Dir = "."
} elseif (Test-Path "$Dir/.git") {
    Write-Host "==> Found an existing checkout at .\$Dir — updating it instead of re-cloning." -ForegroundColor Cyan
    git -C $Dir fetch --depth 1 origin $Ref
    git -C $Dir reset --hard "origin/$Ref"
} elseif (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "==> Cloning $RepoOwner/$RepoName (branch: $Ref) into .\$Dir ..." -ForegroundColor Cyan
    git clone --depth 1 --branch $Ref $RepoUrl $Dir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[x] git clone failed. Check your network / the repo URL and try again." -ForegroundColor Red
        exit 1
    }
} else {
    # No git — fall back to a plain zip download+extract so this still works on
    # a bare-minimum machine (Invoke-WebRequest/Expand-Archive ship with Windows).
    Write-Host "==> git not found — downloading the $Ref zip instead..." -ForegroundColor Cyan
    $ZipUrl = "https://github.com/$RepoOwner/$RepoName/archive/refs/heads/$Ref.zip"
    $TmpZip = Join-Path $env:TEMP "osprey-$Ref.zip"
    $TmpExtract = Join-Path $env:TEMP "osprey-extract-$(Get-Random)"
    try {
        Invoke-WebRequest -Uri $ZipUrl -OutFile $TmpZip -UseBasicParsing
    } catch {
        Write-Host "[x] Download failed (tried $ZipUrl). Install git and try again, or download" -ForegroundColor Red
        Write-Host "    the repo manually from https://github.com/$RepoOwner/$RepoName" -ForegroundColor Red
        exit 1
    }
    Expand-Archive -Path $TmpZip -DestinationPath $TmpExtract -Force
    $extracted = Get-ChildItem $TmpExtract | Select-Object -First 1
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Move-Item -Path (Join-Path $extracted.FullName "*") -Destination $Dir -Force
    Remove-Item -Recurse -Force $TmpZip, $TmpExtract -ErrorAction SilentlyContinue
}

Set-Location $Dir
Write-Host "==> Handing off to the setup wizard (scripts\install.ps1)..." -ForegroundColor Cyan
Write-Host ""

& powershell -ExecutionPolicy Bypass -File scripts\install.ps1
