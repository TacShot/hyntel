$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

function Write-Log {
    param([string]$Message)
    Write-Host "[audit] $Message"
}

function Ensure-Ready {
    if (-not (Test-Path $VenvPython)) {
        throw "Virtual environment not found at $VenvPython. Run .\setup.ps1 first."
    }
}

function Invoke-TerminalInterface {
    Write-Log "Launching the terminal interface"
    & $VenvPython -m security_audit_tool.terminal_ui
    exit $LASTEXITCODE
}

function Invoke-AuditGui {
    Write-Log "Launching the GUI"
    & $VenvPython -m security_audit_tool.launcher
    exit $LASTEXITCODE
}

function Show-Menu {
    Write-Host ""
    Write-Host "Choose an option:"
    Write-Host "  1) Use Terminal interface"
    Write-Host "  2) Launch GUI"
    Write-Host "  3) Exit"
    Write-Host ""
}

function Invoke-Selection {
    param([string]$Selection)

    switch ($Selection) {
        "1" { Invoke-TerminalInterface }
        "2" { Invoke-AuditGui }
        "3" { Write-Log "Exiting"; exit 0 }
        "0" { Write-Log "Exiting"; exit 0 }
        "exit" { Write-Log "Exiting"; exit 0 }
        default { Write-Warning "Invalid selection: $Selection" }
    }
}

Ensure-Ready

if ($args.Length -gt 0) {
    switch ($args[0]) {
        "--gui" { Invoke-AuditGui }
        "gui" { Invoke-AuditGui }
        "2" { Invoke-AuditGui }
        "--tui" { Invoke-TerminalInterface }
        "tui" { Invoke-TerminalInterface }
        "1" { Invoke-TerminalInterface }
        "3" { Write-Log "Exiting"; exit 0 }
        default { Invoke-Selection -Selection $args[0] }
    }
}

while ($true) {
    Show-Menu
    $selection = Read-Host "Enter option number"
    Invoke-Selection -Selection $selection
}
