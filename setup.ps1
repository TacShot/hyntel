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
        throw "winget is required on Windows to install Python automatically. Please install Python manually from https://www.python.org/downloads/"
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
        $installResult = winget install --id $packageId --exact --accept-package-agreements --accept-source-agreements 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Refresh PATH to include newly installed Python
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            # Give the system a moment to recognize the new installation
            Start-Sleep -Seconds 2

            if (Test-Python3) {
                Write-Log "Python 3 installed successfully"
                return
            }
        }
    }

    throw "winget could not install a supported Python 3 package automatically. Please install Python manually from https://www.python.org/downloads/"
}

function Test-Python3 {
    if (Test-Command "py") {
        $output = & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    if (Test-Command "python") {
        $output = & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    return $false
}

function Resolve-Python {
    if (Test-Command "py") {
        $output = & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            return "py -3"
        }
    }

    if (Test-Command "python") {
        $output = & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            return "python"
        }
    }
    throw "Python 3 was not found after installation."
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$PythonArgs
    )

    if ($PythonCommand -eq "python") {
        & python @PythonArgs
        return
    }

    & py -3 @PythonArgs
}

function Setup-Venv {
    param([string]$PythonCommand)

    Write-Log "Creating virtual environment in $RootDir\.venv"
    $venvResult = Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-m", "venv", "$RootDir\.venv") 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment. Make sure Python 3 includes the venv module. Error: $venvResult"
    }

    $PythonExe = Join-Path $RootDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $PythonExe)) {
        throw "Virtual environment creation did not produce $PythonExe"
    }

    Write-Log "Installing project in editable mode"
    & $PythonExe -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upgrade pip in virtual environment"
    }

    & $PythonExe -m pip install -e $RootDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install project in virtual environment"
    }
}

try {
    Install-Python
    $pythonCommand = Resolve-Python
    Setup-Venv $pythonCommand

    Write-Log "Setup complete"
    Write-Log "Run audits with: .\audit.ps1"
    Write-Log "Launch GUI with: .\audit.ps1 --gui"
} catch {
    Write-Error "Setup failed: $_"
    Write-Host "Please install Python 3 manually from https://www.python.org/downloads/ and run this script again."
    exit 1
}
