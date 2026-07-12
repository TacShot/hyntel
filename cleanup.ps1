# ---------------------------------------------------------------------------
# cleanup.ps1 – Remove audit artifacts, venv, cached files, and Desktop
#               reports so that sensitive details of previously audited
#               machines are not left behind.
#
# Usage:
#   .\cleanup.ps1            # Interactive – prompts before each section
#   .\cleanup.ps1 -Force    # Non-interactive – skip all prompts
# ---------------------------------------------------------------------------

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ROOT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Log($msg)  { Write-Host "[cleanup] $msg" }
function Warn($msg)  { Write-Warning "[cleanup] $msg" }

function PromptYesNo($label) {
    if ($Force) { return $true }
    $answer = Read-Host "  $label [y/N]"
    return ($answer -match '^(y|yes|1|true)$')
}

# Secure-delete a file: overwrite 3 passes then remove
function SecureDeleteFile($path) {
    if (-not (Test-Path $path -PathType Leaf)) { return }
    try {
        $size = (Get-Item $path).Length
        if ($size -gt 0) {
            $patterns = @([byte[]]::new($size), [byte[]]::new($size), [byte[]]::new($size))
            for ($i = 0; $i -lt $size; $i++) {
                $patterns[0][$i] = 0x00
                $patterns[1][$i] = 0xFF
                $patterns[2][$i] = 0xAA
            }
            foreach ($pat in $patterns) {
                [System.IO.File]::WriteAllBytes($path, $pat)
            }
            # Truncate to zero
            [System.IO.File]::WriteAllBytes($path, [byte[]]::new(0))
        }
        Remove-Item $path -Force
    } catch {
        Warn "Could not securely delete ${path}: $($_.Exception.Message)"
    }
}

# Secure-delete a directory tree
function SecureDeleteDir($dir) {
    if (-not (Test-Path $dir -PathType Container)) { return }
    try {
        # Securely delete all regular files inside
        Get-ChildItem $dir -Recurse -File | ForEach-Object {
            SecureDeleteFile $_.FullName
        }
        # Remove remaining directories bottom-up
        Get-ChildItem $dir -Recurse -Directory | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object {
            Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
        }
        Remove-Item $dir -Force -Recurse -ErrorAction SilentlyContinue
    } catch {
        Warn "Could not securely delete ${dir}: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 1. Artifacts directory
# ---------------------------------------------------------------------------

$ARTIFACTS_DIR = Join-Path $ROOT_DIR "artifacts"
if (Test-Path $ARTIFACTS_DIR -PathType Container) {
    if (PromptYesNo "Remove artifacts directory ($ARTIFACTS_DIR)?") {
        Log "Securely deleting artifacts directory"
        SecureDeleteDir $ARTIFACTS_DIR
        Log "artifacts/ removed"
    } else {
        Log "Skipped artifacts cleanup"
    }
} else {
    Log "No artifacts directory found"
}

# ---------------------------------------------------------------------------
# 2. Desktop-exported reports
# ---------------------------------------------------------------------------

$DESKTOP_BASE = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
foreach ($dirName in @("SecurityAuditReports", "Hyntel Report")) {
    $DESK_DIR = Join-Path $DESKTOP_BASE $dirName
    if (Test-Path $DESK_DIR -PathType Container) {
        if (PromptYesNo "Remove Desktop reports ($DESK_DIR)?") {
            Log "Securely deleting $DESK_DIR"
            SecureDeleteDir $DESK_DIR
            Log "$dirName/ removed"
        } else {
            Log "Skipped $dirName cleanup"
        }
    } else {
        Log "No $dirName directory on Desktop"
    }
}

# ---------------------------------------------------------------------------
# 3. __pycache__ and .pyc / .pyo files
# ---------------------------------------------------------------------------

$PYCACHE_COUNT = 0
if (PromptYesNo "Remove __pycache__ directories and bytecode files?") {
    Log "Scanning for __pycache__ directories and .pyc/.pyo files"
    Get-ChildItem $ROOT_DIR -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\\.venv\\' } |
        ForEach-Object {
            SecureDeleteDir $_.FullName
            $PYCACHE_COUNT++
        }
    Get-ChildItem $ROOT_DIR -Recurse -File -Include "*.pyc","*.pyo" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\\.venv\\' } |
        ForEach-Object {
            SecureDeleteFile $_.FullName
            $PYCACHE_COUNT++
        }
    Log "Removed $PYCACHE_COUNT cache item(s)"
} else {
    Log "Skipped pycache cleanup"
}

# ---------------------------------------------------------------------------
# 4. .egg-info directories
# ---------------------------------------------------------------------------

$EGG_INFO_COUNT = 0
if (PromptYesNo "Remove .egg-info build directories?") {
    Get-ChildItem $ROOT_DIR -Directory -Filter "*.egg-info" -ErrorAction SilentlyContinue | ForEach-Object {
        Log "Removing $($_.FullName)"
        Remove-Item $_.FullName -Recurse -Force
        $EGG_INFO_COUNT++
    }
    Log "Removed $EGG_INFO_COUNT .egg-info directory/directories"
} else {
    Log "Skipped .egg-info cleanup"
}

# ---------------------------------------------------------------------------
# 5. VERIFICATION_SUMMARY.md
# ---------------------------------------------------------------------------

$VERFILE = Join-Path $ROOT_DIR "VERIFICATION_SUMMARY.md"
if (Test-Path $VERFILE -PathType Leaf) {
    if (PromptYesNo "Remove VERIFICATION_SUMMARY.md?") {
        Log "Securely deleting VERIFICATION_SUMMARY.md"
        SecureDeleteFile $VERFILE
        Log "VERIFICATION_SUMMARY.md removed"
    } else {
        Log "Skipped VERIFICATION_SUMMARY.md cleanup"
    }
} else {
    Log "No VERIFICATION_SUMMARY.md found"
}

# ---------------------------------------------------------------------------
# 6. .venv directory
# ---------------------------------------------------------------------------

$VENV_DIR = Join-Path $ROOT_DIR ".venv"
if (Test-Path $VENV_DIR -PathType Container) {
    if (PromptYesNo "Remove virtual environment (.venv/)? You will need to re-run setup.ps1.") {
        Log "Removing .venv directory (standard delete - no sensitive data inside venv)"
        Remove-Item $VENV_DIR -Recurse -Force
        Log ".venv/ removed"
    } else {
        Log "Skipped .venv cleanup"
    }
} else {
    Log "No .venv directory found"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

Log "Cleanup complete"
