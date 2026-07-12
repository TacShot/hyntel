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
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath"
}

function Get-CommonPythonPaths {
    return @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe"
    )
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$PythonArgs
    )

    if ($PythonCommand -eq "py -3") {
        & py -3 @PythonArgs
        return
    }

    & $PythonCommand @PythonArgs
}

function Test-PythonModule {
    param(
        [string]$PythonCommand,
        [string]$ModuleName
    )

    Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-c", "import $ModuleName") *> $null
    return ($LASTEXITCODE -eq 0)
}

function Resolve-Python {
    Refresh-Path

    foreach ($path in Get-CommonPythonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    if (Test-Command "py") {
        & py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" *> $null
        if ($LASTEXITCODE -eq 0) {
            return "py -3"
        }
    }

    if (Test-Command "python") {
        & python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" *> $null
        if ($LASTEXITCODE -eq 0) {
            return "python"
        }
    }

    return $null
}

function Install-Python {
    if (Resolve-Python) {
        Write-Log "Python 3 already installed"
        return
    }

    if (-not (Test-Command "winget")) {
        throw "winget is required on Windows to install Python automatically. Please install Python manually from https://www.python.org/downloads/"
    }

    $packageIds = @(
        "Python.Python.3.13",
        "Python.Python.3.12",
        "Python.Python.3.11",
        "Python.Python.3.10",
        "Python.Python.3.9"
    )

    foreach ($packageId in $packageIds) {
        Write-Log "Trying to install Python with winget package $packageId"
        & winget install --id $packageId --exact --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Refresh-Path
            Start-Sleep -Seconds 2
            if (Resolve-Python) {
                Write-Log "Python 3 installed successfully"
                return
            }
        }
    }

    throw "winget could not install a supported Python 3 package automatically. Please install Python manually from https://www.python.org/downloads/"
}

function Ensure-Pip {
    param([string]$PythonCommand)

    Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-m", "pip", "--version") *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Log "Bootstrapping pip"
    Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-m", "ensurepip", "--upgrade")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not bootstrap pip for the detected Python 3 interpreter."
    }
}

function Ensure-Tkinter {
    param([string]$PythonCommand)

    if (Test-PythonModule -PythonCommand $PythonCommand -ModuleName "tkinter") {
        Write-Log "Tkinter GUI support available"
        return
    }

    Write-Warning "Tkinter GUI support is not available for the detected Python."
    Write-Warning "The terminal interface will still work, but .\audit.ps1 --gui may fall back to terminal mode."
}

function Get-OutdatedPackages {
    param([string]$PythonExe)

    $json = & $PythonExe -m pip list --outdated --format=json
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($json)) {
        return @()
    }

    return @($json | ConvertFrom-Json)
}

function Prompt-PackageUpdates {
    param([string]$PythonExe)

    $packages = @(Get-OutdatedPackages -PythonExe $PythonExe)
    if ($packages.Count -eq 0) {
        Write-Log "Python packages are up to date"
        return
    }

    Write-Log "Python package updates are available:"
    for ($i = 0; $i -lt $packages.Count; $i++) {
        $number = $i + 1
        $package = $packages[$i]
        Write-Host ("  {0}) {1} {2} -> {3}" -f $number, $package.name, $package.version, $package.latest_version)
    }

    $updateAll = Read-Host "Update all listed Python packages? [y/N]"
    if ($updateAll -match "^(y|yes)$") {
        Write-Log "Updating all outdated Python packages"
        $names = @($packages | ForEach-Object { $_.name })
        & $PythonExe -m pip install --upgrade @names
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to update Python packages"
        }
        return
    }

    $skipInput = Read-Host "Enter package numbers to skip from update (1-$($packages.Count)), separated by spaces, or 0 for none"
    if ([string]::IsNullOrWhiteSpace($skipInput)) {
        $skipInput = "0"
    }

    $skipNumbers = @{}
    foreach ($token in ($skipInput -split "[,\s]+")) {
        if ($token -match "^\d+$" -and $token -ne "0") {
            $skipNumbers[[int]$token] = $true
        }
    }

    $selected = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $packages.Count; $i++) {
        $number = $i + 1
        $package = $packages[$i]
        if ($skipNumbers.ContainsKey($number)) {
            Write-Log "Skipping update for $($package.name)"
        } else {
            $selected.Add($package.name)
        }
    }

    if ($selected.Count -eq 0) {
        Write-Log "No Python package updates selected"
        return
    }

    Write-Log "Updating selected Python packages"
    & $PythonExe -m pip install --upgrade @selected
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to update selected Python packages"
    }
}

function Setup-Venv {
    param([string]$PythonCommand)

    Write-Log "Creating virtual environment in $RootDir\.venv"
    Invoke-Python -PythonCommand $PythonCommand -PythonArgs @("-m", "venv", "$RootDir\.venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment. Make sure Python 3 includes the venv module."
    }

    $pythonExe = Join-Path $RootDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $pythonExe)) {
        throw "Virtual environment creation did not produce $pythonExe"
    }

    Write-Log "Installing project in editable mode"
    & $pythonExe -m pip install --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upgrade Python packaging tools in virtual environment"
    }

    & $pythonExe -m pip install -e $RootDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install project in virtual environment"
    }

    Prompt-PackageUpdates -PythonExe $pythonExe
}

try {
    Install-Python
    $pythonCommand = Resolve-Python
    if (-not $pythonCommand) {
        throw "A Python 3 interpreter could not be found after installation."
    }

    Ensure-Pip -PythonCommand $pythonCommand
    Ensure-Tkinter -PythonCommand $pythonCommand
    Setup-Venv -PythonCommand $pythonCommand

    Write-Log "Setup complete"
    Write-Log "Run audits with: .\audit.ps1"
    Write-Log "Launch GUI with: .\audit.ps1 --gui"
} catch {
    Write-Error "Setup failed: $_"
    Write-Host "Please install Python 3 manually from https://www.python.org/downloads/ and run this script again."
    exit 1
}
