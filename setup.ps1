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

    if (Test-Command "py") {
        try {
            $null = & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>&1
            if ($LASTEXITCODE -eq 0) { return "py -3" }
        } catch {}
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
        Write-Log "Trying to install Python via winget: $packageId"
        try {
            winget install --id $packageId --exact --accept-package-agreements --accept-source-agreements
            if ($LASTEXITCODE -eq 0) {
                Refresh-Path
                if (Test-Python3) {
                    Write-Log "Python installed successfully via winget."
                    return $true
                }
            }
        } catch {}
    }
    return $false
}

function Install-Python-Via-Web {
    Write-Log "Downloading Python installer from python.org..."
    $pythonUrl = "https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe"
    $installerPath = "$env:TEMP\python_installer.exe"

    Write-Log "Downloading from $pythonUrl (this may take a minute)..."
    Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath -UseBasicParsing

    Write-Log "Running Python installer silently..."
    Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_launcher=1" -Wait

    Remove-Item $installerPath -Force
    Refresh-Path

    if (Test-Python3) {
        Write-Log "Python installed successfully via web download."
        return $true
    }
    return $false
}

function Install-Python {
    if (Test-Python3) {
        Write-Log "Python 3 is already installed."
        return
    }

    Write-Log "Python 3 not found. Attempting automatic installation..."

    if (Test-Command "winget") {
        $success = Install-Python-Via-Winget
        if ($success) { return }
        Write-Log "winget install did not result in a working Python. Trying direct download..."
    } else {
        Write-Log "winget not available. Trying direct download..."
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
    Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-m", "venv", "$RootDir\.venv")
    $PythonExe = Join-Path $RootDir ".venv\Scripts\python.exe"
    Write-Log "Installing project in editable mode"
    & $PythonExe -m pip install --upgrade pip
    & $PythonExe -m pip install -e $RootDir
}

# --- Main ---
Install-Python
$pythonCommand = Resolve-Python
Setup-Venv $pythonCommand
Write-Log "Setup complete"
Write-Log "Run audits with: .\audit.ps1"
Write-Log "Launch GUI with: .\audit.ps1 --gui"