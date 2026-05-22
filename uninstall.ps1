# iocscan project-only uninstall (PowerShell).
#
# Removes ONLY files and directories created by this project. System-wide
# tools (python, git, gh, pip, etc.) and other Python projects are NOT
# touched.
#
# Each destructive step asks for confirmation before running.
#
# Usage:
#   .\uninstall.ps1
#
# If PowerShell blocks script execution, allow it for the current session:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$UserData   = Join-Path $env:USERPROFILE ".iocscan"

function Confirm-Action {
    param([string]$Prompt)
    $reply = Read-Host "  $Prompt [y/N]"
    return $reply -match '^[Yy]$'
}

Write-Host "==> iocscan project-only uninstall"
Write-Host "    Project dir: $ProjectDir"
Write-Host "    User data:   $UserData"
Write-Host ""
Write-Host "    This script will NOT touch python, git, gh, pip, or any other"
Write-Host "    system-wide tool. Other projects on this machine are unaffected."
Write-Host ""

# -----------------------------------------------------------------------------
# Step 1 — user data (~\.iocscan\): API keys, TI cache, Tranco whitelist
# -----------------------------------------------------------------------------
if (Test-Path $UserData) {
    Write-Host "[1/3] User data at $UserData"
    Write-Host "      Contains: config.toml (API keys), cache.db (TI lookups),"
    Write-Host "                tranco-1k.txt (whitelist cache)."

    $ConfigToml = Join-Path $UserData "config.toml"
    if ((Test-Path $ConfigToml) -and (Confirm-Action "Back up config.toml to ~\iocscan-config-backup.toml first?")) {
        $Backup = Join-Path $env:USERPROFILE "iocscan-config-backup.toml"
        Copy-Item $ConfigToml $Backup -Force
        Write-Host "      -> backup saved (NTFS ACLs apply; POSIX 0600 not enforced on Windows)."
    }

    if (Confirm-Action "Remove $UserData?") {
        Remove-Item $UserData -Recurse -Force
        Write-Host "      removed."
    } else {
        Write-Host "      skipped."
    }
} else {
    Write-Host "[1/3] $UserData does not exist - skipped."
}
Write-Host ""

# -----------------------------------------------------------------------------
# Step 2 — project venv (.venv\): httpx, rich, pytest, ...
# -----------------------------------------------------------------------------
$Venv = Join-Path $ProjectDir ".venv"
if (Test-Path $Venv) {
    Write-Host "[2/3] Project venv at $Venv"
    Write-Host "      Contains httpx, rich, tomli-w (and pytest/coverage if dev extras"
    Write-Host "      were installed). Only this venv is affected - system Python and"
    Write-Host "      other projects' venvs are untouched."
    if (Confirm-Action "Remove $Venv?") {
        Remove-Item $Venv -Recurse -Force
        Write-Host "      removed."
    } else {
        Write-Host "      skipped."
    }
} else {
    Write-Host "[2/3] $Venv does not exist - skipped."
}
Write-Host ""

# -----------------------------------------------------------------------------
# Step 3 — project source tree
# -----------------------------------------------------------------------------
Write-Host "[3/3] Project source tree at $ProjectDir"
Write-Host "      This removes: source code, tests, docs, and the local .git\"
Write-Host "      history. Any uncommitted local changes will be lost."
Write-Host "      Note: the script will delete itself during this step."

if (Confirm-Action "Remove $ProjectDir?") {
    $Parent = Split-Path -Parent $ProjectDir
    # Set-Location out before removing so we don't delete our own CWD.
    Set-Location $Parent
    Remove-Item $ProjectDir -Recurse -Force
    Write-Host "      removed."
} else {
    Write-Host "      skipped."
}
Write-Host ""

Write-Host "==> done."
Write-Host ""
Write-Host "Verify nothing project-specific is left:"
Write-Host "    Test-Path $UserData       # False"
Write-Host "    Test-Path $ProjectDir     # False"
