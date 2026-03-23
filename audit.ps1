$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"
$CliExecutable = Join-Path $RootDir ".venv\Scripts\security-audit.exe"
function Write-Log {
    param([string]$Message)
    Write-Host "[audit] $Message"
}

function Ensure-Ready {
    if (-not (Test-Path $VenvPython)) {
        throw "Virtual environment not found at $VenvPython. Run .\setup.ps1 first."
    }
}

function Detect-OS {
    if ($IsWindows) {
        return "windows"
    }
    throw "audit.ps1 is intended for Windows PowerShell."
}

function Resolve-Executable {
    param([string]$PreferredPath, [string]$ModuleName)

    if (Test-Path $PreferredPath) {
        return @{ Kind = "path"; Value = $PreferredPath }
    }

    return @{ Kind = "module"; Value = $ModuleName }
}

function Invoke-AuditCli {
    param([string[]]$RemainingArgs)

    $resolved = Resolve-Executable -PreferredPath $CliExecutable -ModuleName "security_audit_tool"
    if ($resolved.Kind -eq "path") {
        & $resolved.Value --target-os windows --generate-remediation --save-to-desktop @RemainingArgs
        return
    }

    & $VenvPython -m security_audit_tool --target-os windows --generate-remediation --save-to-desktop @RemainingArgs
}

function Invoke-AuditGui {
    param([string[]]$RemainingArgs)

    & $VenvPython -m security_audit_tool.launcher @RemainingArgs
}

Ensure-Ready
$detectedOs = Detect-OS
Write-Log "Detected OS: $detectedOs"

if ($args.Length -gt 0 -and $args[0] -eq "--gui") {
    $remaining = @()
    if ($args.Length -gt 1) {
        $remaining = $args[1..($args.Length - 1)]
    }
    Write-Log "Launching GUI"
    Invoke-AuditGui -RemainingArgs $remaining
    exit $LASTEXITCODE
}

Write-Log "Running audit and exporting reports"
Invoke-AuditCli -RemainingArgs $args
exit $LASTEXITCODE
