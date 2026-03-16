$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
    param([string]$Message)
    Write-Host "[setup] $Message"
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Install-Python {
    if (Test-Command "python") {
        Write-Log "python already installed"
        return
    }

    if (Test-Command "py") {
        Write-Log "Python launcher already installed"
        return
    }

    if (-not (Test-Command "winget")) {
        throw "winget is required on Windows to install Python automatically."
    }

    Write-Log "Installing Python with winget"
    winget install --id Python.Python.3.12 --exact --accept-package-agreements --accept-source-agreements
}

function Resolve-Python {
    if (Test-Command "python") {
        return "python"
    }
    if (Test-Command "py") {
        return "py -3"
    }
    throw "Python was not found after installation."
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$Args
    )

    if ($PythonCommand -eq "python") {
        & python @Args
        return
    }

    & py -3 @Args
}

function Setup-Venv {
    param([string]$PythonCommand)

    Write-Log "Creating virtual environment in $RootDir\.venv"
    Invoke-Python -PythonCommand $PythonCommand -Args @("-m", "venv", "$RootDir\.venv")

    Write-Log "Installing project in editable mode"
    & "$RootDir\.venv\Scripts\python.exe" -m pip install --upgrade pip
    & "$RootDir\.venv\Scripts\python.exe" -m pip install -e $RootDir
}

Install-Python
$pythonCommand = Resolve-Python
Setup-Venv $pythonCommand

Write-Log "Setup complete"
Write-Log "Activate with: .\.venv\Scripts\Activate.ps1"
Write-Log "Run with: security-audit --help"
