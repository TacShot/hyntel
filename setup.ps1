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
    if (Test-Python3) {
        Write-Log "Python 3 already installed"
        return
    }

    if (-not (Test-Command "winget")) {
        throw "winget is required on Windows to install Python automatically."
    }

    $packageIds = @(
        "Python.Python.3.14",
        "Python.Python.3.13",
        "Python.Python.3.12",
        "Python.Python.3.11",
        "Python.Python.3.10",
        "Python.Python.3.9"
    )

    foreach ($packageId in $packageIds) {
        Write-Log "Trying to install Python with winget package $packageId"
        winget install --id $packageId --exact --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0 -and (Test-Python3)) {
            return
        }
    }

    throw "winget could not install a supported Python 3 package automatically."
}

function Test-Python3 {
    if (Test-Command "python") {
        & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    if (Test-Command "py") {
        & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    return $false
}

function Resolve-Python {
    if (Test-Command "python") {
        & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return "python"
        }
    }
    if (Test-Command "py") {
        & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return "py -3"
        }
    }
    throw "Python 3 was not found after installation."
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
Write-Log "Run audits with: .\audit.ps1"
Write-Log "Launch GUI with: .\audit.ps1 --gui"
