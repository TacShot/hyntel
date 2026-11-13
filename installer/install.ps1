<#>
.SYNOPSIS
    hyntel net-installer for Windows
.DESCRIPTION
    Cross-platform net-installer for hyntel security audit tool.
    Downloads and installs the latest hyntel release with all dependencies.

.EXAMPLE
    # Install latest version
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex

    # Install specific version from source
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --from-source --version 0.1.0

    # Install system-wide (requires admin)
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --target system

    # Uninstall
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --uninstall
#>

param(
    [switch]$FromSource,
    [string]$Version,
    [string]$Prefix,
    [switch]$SkipDeps,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Verbose,
    [ValidateSet('user', 'system')]
    [string]$Target = 'user',
    [switch]$Uninstall,
    [switch]$Help
)

$REPO = "TacShot/hyntel"
$BINARY = "hyntel.exe"
$INSTALLER_VERSION = "0.1.0"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Show-Help {
    @"
hyntel-installer v$INSTALLER_VERSION
Cross-platform net-installer for hyntel security audit tool

Usage: install.ps1 [OPTIONS]

Options:
    --from-source       Build from source instead of downloading pre-built binary
    --version VERSION   Install specific version (default: latest)
    --prefix PATH       Install to custom directory
    --skip-deps         Skip system dependency installation
    --force             Force reinstall even if already installed
    --dry-run           Show what would be done without installing
    --verbose           Verbose output
    --target TARGET     Installation target: user (default) or system
    --uninstall         Uninstall hyntel
    --help              Show this help

Examples:
    # Install latest version for current user
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex

    # Install specific version from source
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --from-source --version 0.1.0

    # Install system-wide (requires admin)
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --target system

    # Uninstall
    iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --uninstall
"@
}

if ($Help) { Show-Help; exit 0 }

# Detect architecture
$ARCH = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
if ($ARCH -eq "AMD64") { $ASSET_PATTERN = "hyntel-x86_64-pc-windows-msvc" }
elseif ($ARCH -eq "ARM64") { $ASSET_PATTERN = "hyntel-aarch64-pc-windows-msvc" }
else { Write-Error "Unsupported architecture: $ARCH"; exit 1 }

$BINARY_NAME = "hyntel.exe"

function Get-InstallDir {
    if ($Prefix) { return $Prefix }
    if ($Target -eq 'system') { return "C:\Program Files\hyntel" }
    return Join-Path $env:LOCALAPPDATA "hyntel\bin"
}

function Is-Installed {
    $installDir = Get-InstallDir
    return Test-Path (Join-Path $installDir $BINARY_NAME)
}

function Get-LatestVersion {
    Write-Info "Fetching latest version..."
    $url = "https://api.github.com/repos/$REPO/releases/latest"
    $response = Invoke-RestMethod -Uri $url -Headers @{ "Accept" = "application/vnd.github.v3+json" }
    return $response.tag_name.TrimStart('v')
}

function Install-Dependencies {
    Write-Info "Checking dependencies..."
    # Check for winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "winget found, checking for required packages..."
        # Add any Windows-specific dependencies here if needed
    }
    elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info "Chocolatey found..."
    }
    elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Info "Scoop found..."
    }
    else {
        Write-Warn "No package manager found (winget/choco/scoop). Skipping system dependencies."
    }
}

function Install-Binary {
    param($version)
    $assetName = "${ASSET_PATTERN}-${version}.zip"
    $downloadUrl = "https://github.com/$REPO/releases/download/v${version}/$assetName"

    Write-Info "Downloading $BINARY $version from $downloadUrl"

    $tempDir = [System.IO.Path]::GetTempPath() + "hyntel-install-" + [Guid]::NewGuid()
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $archivePath = Join-Path $tempDir "$assetName"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
    }
    catch {
        Write-Error "Failed to download from $downloadUrl: $_"
        exit 1
    }

    Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force

    $binaryPath = Get-ChildItem -Path $tempDir -Filter "$BINARY_NAME" -Recurse | Select-Object -First 1
    if (-not $binaryPath) {
        Write-Error "Binary not found in archive"
        exit 1
    }

    $installDir = Get-InstallDir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    Copy-Item $binaryPath.FullName (Join-Path $installDir $BINARY_NAME) -Force

    Write-Success "Installed to $installDir\$BINARY_NAME"
}

function Install-FromSource {
    param($version)
    Write-Info "Building hyntel $version from source..."

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Info "Rust toolchain not found. Installing via rustup..."
        $script = "Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile 'rustup-init.exe'; .\rustup-init.exe -y"
        Invoke-Expression $script
        Write-Success "Rust toolchain installed. Please restart your shell."
    }

    $tempDir = [System.IO.Path]::GetTempPath() + "hyntel-build-" + [Guid]::NewGuid()
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    git clone --branch "v$version" --depth 1 "https://github.com/$REPO.git" $tempDir
    Set-Location $tempDir
    cargo build --release --workspace

    $installDir = Get-InstallDir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    foreach ($binary in @("hyntel.exe", "hyntel-cli.exe", "hyntel-tui.exe", "hyntel-gui.exe")) {
        $src = "target\release\$binary"
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $installDir $binary) -Force
        }
    }

    Write-Success "Built and installed from source"
}

function Create-Shortcuts {
    $installDir = Get-InstallDir
    $binary = Join-Path $installDir $BINARY_NAME

    # Create Start Menu shortcut
    $shortcutPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\HYNTEL Security Audit.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $binary
    $shortcut.Description = "HYNTEL Security Audit Tool"
    $shortcut.Save()

    Write-Success "Created Start Menu shortcut"
}

function Add-ToPath {
    $installDir = Get-InstallDir
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -notlike "*$installDir*") {
        $newPath = $currentPath + ";" + $installDir
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Success "Added $installDir to user PATH"
        Write-Warn "Please restart your terminal for PATH changes to take effect"
    }
}

function Uninstall {
    Write-Info "Uninstalling hyntel..."

    $installDir = Get-InstallDir
    $binary = Join-Path $installDir $BINARY_NAME

    if (Test-Path $binary) {
        Remove-Item $binary -Force
        Write-Success "Removed binary: $binary"
    }

    # Remove Start Menu shortcut
    $shortcutPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\HYNTEL Security Audit.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Success "Removed Start Menu shortcut"
    }

    Write-Success "Uninstall complete."
    exit 0
}

function Print-PostInstallInfo {
    $installDir = Get-InstallDir
    Write-Host
    Write-Success "Installation complete!"
    Write-Host "Binary installed to: $installDir"
    Write-Host "Run 'hyntel --help' to get started"
    Write-Host
    Write-Host "Note: Please restart your terminal for PATH changes to take effect."
}

# Main execution
Write-Host "hyntel-installer v$INSTALLER_VERSION" -ForegroundColor Cyan
Write-Host "Cross-platform net-installer for hyntel security audit tool"
Write-Host

# Parse arguments already done by PowerShell param block

if ($Uninstall) { Uninstall; exit 0 }

if (-not $Version) {
    $Version = Get-LatestVersion
    Write-Info "Latest version: $Version"
}

if ($DryRun) {
    Write-Info "[DRY RUN] Would install $BINARY $Version for $ASSET_PATTERN"
    exit 0
}

if (-not $Force -and (Is-Installed)) {
    Write-Warn "$BINARY_NAME is already installed. Use --force to reinstall."
    exit 0
}

if (-not $SkipDeps) {
    Install-Dependencies
}

if ($FromSource) {
    Install-FromSource -version $Version
} else {
    Install-Binary -version $Version
}

Create-Shortcuts
Add-ToPath

Write-Host
Write-Success "Installation complete!"
Write-Host "Binary installed to: $(Get-InstallDir)"
Write-Host "Run 'hyntel --help' to get started"
Write-Host
Write-Host "Note: Please restart your terminal for PATH changes to take effect."