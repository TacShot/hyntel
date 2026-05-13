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

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Test-Python3 {
    Refresh-Path

    # Check common install paths directly first (avoids py.exe launcher issues)
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe"
    )
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $env:Path = (Split-Path $path) + ";" + $env:Path
            return $true
        }
    }

    # Try py launcher (silently)
    if (Test-Command "py") {
        try {
            $null = & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch {}
    }

    # Try python command (silently)
    if (Test-Command "python") {
        try {
            $null = & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch {}
    }

    return $false
}

function Resolve-Python {
    # Check common install paths directly first
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe"
    )
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $env:Path = (Split-Path $path) + ";" + $env:Path
            return "python"
        }
    }

    if (-not (Test-Command "winget")) {
        throw "winget is required on Windows to install Python automatically. Please install Python manually from https://www.python.org/downloads/"
    }

    if (Test-Command "python") {
        try {
            $null = & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
            if ($LASTEXITCODE -eq 0) { return "python" }
        } catch {}
    }

    throw "Python 3 not found after installation. Please restart PowerShell and try again."
}

function Install-Python-Via-Winget {
    $packageIds = @(
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

    Remove-Item $installerPath -Force
    Refresh-Path

    if (Test-Python3) {
        Write-Log "Python installed successfully via web download."
        return $true
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

    $success = Install-Python-Via-Web
    if ($success) { return }

    throw "Could not install Python automatically. Please install Python 3 manually from https://www.python.org/downloads/ and re-run this script."
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
    if ($PythonCommand -eq "python3") {
        & python3 @PythonArgs
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
