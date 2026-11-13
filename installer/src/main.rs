//! hyntel-installer: Cross-platform net-installer for hyntel security audit tool
//!
//! This installer:
//! 1. Detects platform and architecture
//! 2. Checks/installs Rust toolchain
//! 3. Installs system dependencies per platform
//! 4. Downloads pre-built binary OR builds from source
//! 5. Installs to system/user location
//! 6. Creates desktop entries/shortcuts

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use dirs;
use reqwest::blocking::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const GITHUB_REPO: &str = "TacShot/hyntel";
const BINARY_NAME: &str = "hyntel";
const INSTALLER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(name = "hyntel-installer", version, about = "Cross-platform net-installer for hyntel security audit tool", disable_version_flag = true)]
struct Args {
    /// Install from source instead of pre-built binary
    #[arg(long)]
    from_source: bool,

    /// Install specific version (default: latest)
    #[arg(long)]
    version: Option<String>,

    /// Install to custom directory
    #[arg(long)]
    prefix: Option<PathBuf>,

    /// Skip system dependency installation
    #[arg(long)]
    skip_deps: bool,

    /// Force reinstall even if already installed
    #[arg(long)]
    force: bool,

    /// Uninstall hyntel
    #[arg(long)]
    uninstall: bool,

    /// Dry run - show what would be done
    #[arg(long)]
    dry_run: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Installation target: user (default) or system
    #[arg(long, value_enum, default_value = "user")]
    target: InstallTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum InstallTarget {
    User,
    System,
}

#[derive(Debug, Deserialize, Serialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
    prerelease: bool,
    draft: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[derive(Debug, Clone)]
struct PlatformInfo {
    os: &'static str,
    arch: &'static str,
    asset_pattern: &'static str,
    package_manager: PackageManager,
    install_cmd: &'static str,
    deps: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Brew,
    Winget,
    Scoop,
    Choco,
    None,
}

impl PlatformInfo {
    fn detect() -> Result<Self> {
        let os = env::consts::OS;
        let arch = env::consts::ARCH;

        match (os, arch) {
            ("linux", "x86_64") => Ok(PlatformInfo {
                os: "linux",
                arch: "x86_64",
                asset_pattern: "hyntel-x86_64-unknown-linux-gnu",
                package_manager: detect_linux_pm(),
                install_cmd: "install",
                deps: LINUX_DEPS,
            }),
            ("linux", "aarch64") => Ok(PlatformInfo {
                os: "linux",
                arch: "aarch64",
                asset_pattern: "hyntel-aarch64-unknown-linux-gnu",
                package_manager: detect_linux_pm(),
                install_cmd: "install",
                deps: LINUX_DEPS,
            }),
            ("macos", "x86_64") => Ok(PlatformInfo {
                os: "macos",
                arch: "x86_64",
                asset_pattern: "hyntel-x86_64-apple-darwin",
                package_manager: PackageManager::Brew,
                install_cmd: "install",
                deps: MACOS_DEPS,
            }),
            ("macos", "aarch64") => Ok(PlatformInfo {
                os: "macos",
                arch: "aarch64",
                asset_pattern: "hyntel-aarch64-apple-darwin",
                package_manager: PackageManager::Brew,
                install_cmd: "install",
                deps: MACOS_DEPS,
            }),
            ("windows", "x86_64") => Ok(PlatformInfo {
                os: "windows",
                arch: "x86_64",
                asset_pattern: "hyntel-x86_64-pc-windows-msvc",
                package_manager: PackageManager::Winget,
                install_cmd: "install",
                deps: WINDOWS_DEPS,
            }),
            _ => Err(anyhow!("Unsupported platform: {}-{}", os, arch)),
        }
    }

    fn asset_name(&self, version: &str) -> String {
        if self.os == "windows" {
            format!("{}-{}.zip", self.asset_pattern, version)
        } else {
            format!("{}-{}.tar.gz", self.asset_pattern, version)
        }
    }

    fn binary_name(&self) -> &str {
        if self.os == "windows" {
            "hyntel.exe"
        } else {
            "hyntel"
        }
    }
}

const LINUX_DEPS: &[&str] = &[
    "pkg-config",
    "libssl-dev",
    "libudev-dev",
    "libgtk-3-dev",
    "libwebkit2gtk-4.0-dev",
    "libayatana-appindicator3-dev",
    "librsvg2-dev",
];

const MACOS_DEPS: &[&str] = &[];

const WINDOWS_DEPS: &[&str] = &[];

fn detect_linux_pm() -> PackageManager {
    if Path::new("/usr/bin/apt").exists() || Path::new("/bin/apt").exists() {
        PackageManager::Apt
    } else if Path::new("/usr/bin/dnf").exists() || Path::new("/bin/dnf").exists() {
        PackageManager::Dnf
    } else if Path::new("/usr/bin/pacman").exists() || Path::new("/bin/pacman").exists() {
        PackageManager::Pacman
    } else {
        PackageManager::None
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        println!("hyntel-installer v{}", INSTALLER_VERSION);
        println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);
    }

    if args.uninstall {
        return uninstall(&args);
    }

    let platform = PlatformInfo::detect()?;
    if args.verbose {
        println!("Detected platform: {} {}", platform.os, platform.arch);
    }

    let version = if let Some(ref v) = args.version {
        v.clone()
    } else {
        fetch_latest_version()?
    };

    if args.verbose {
        println!("Target version: {}", version);
    }

    if args.dry_run {
        println!("[DRY RUN] Would install hyntel {} for {}", version, platform.asset_pattern);
        return Ok(());
    }

    // Check if already installed
    if !args.force && is_installed(&args) {
        println!("hyntel {} is already installed. Use --force to reinstall.", version);
        return Ok(());
    }

    // Install system dependencies
    if !args.skip_deps {
        install_system_deps(&platform, args.verbose)?;
    }

    // Install hyntel
    if args.from_source {
        install_from_source(&version, &args)?;
    } else {
        install_binary(&platform, &version, &args)?;
    }

    // Create desktop entries/shortcuts
    create_shortcuts(&args)?;

    println!("✓ hyntel {} installed successfully!", version);
    print_post_install_info(&args);

    Ok(())
}

fn fetch_latest_version() -> Result<String> {
    let client = Client::builder()
        .user_agent("hyntel-installer")
        .build()?;

    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    let release: GitHubRelease = client.get(&url).send()?.json()?;

    Ok(release.tag_name.trim_start_matches('v').to_string())
}

fn is_installed(args: &Args) -> bool {
    let install_dir = get_install_dir(args);
    let binary = install_dir.join(if cfg!(target_os = "windows") { "hyntel.exe" } else { "hyntel" });
    binary.exists()
}

fn get_install_dir(args: &Args) -> PathBuf {
    if let Some(prefix) = &args.prefix {
        return prefix.clone();
    }

    match args.target {
        InstallTarget::System => {
            if cfg!(target_os = "windows") {
                PathBuf::from("C:\\Program Files\\hyntel")
            } else {
                PathBuf::from("/usr/local/bin")
            }
        }
        InstallTarget::User => {
            if let Some(home) = dirs::home_dir() {
                home.join(".local").join("bin")
            } else {
                PathBuf::from(".")
            }
        }
    }
}

fn install_system_deps(platform: &PlatformInfo, verbose: bool) -> Result<()> {
    if verbose {
        println!("Installing system dependencies...");
    }

    match platform.package_manager {
        PackageManager::Apt => {
            run_cmd("apt", &["update"], verbose)?;
            run_cmd("apt", &["install", "-y", &platform.deps.join(" ")], verbose)?;
        }
        PackageManager::Dnf => {
            run_cmd("dnf", &["install", "-y", &platform.deps.join(" ")], verbose)?;
        }
        PackageManager::Pacman => {
            run_cmd("pacman", &["-S", "--needed", "--noconfirm", &platform.deps.join(" ")], verbose)?;
        }
        PackageManager::Brew => {
            for dep in platform.deps {
                run_cmd("brew", &["install", dep], verbose)?;
            }
        }
        PackageManager::Winget => {
            for dep in platform.deps {
                run_cmd("winget", &["install", "-e", "--id", dep], verbose)?;
            }
        }
        PackageManager::None => {
            if verbose {
                println!("No package manager detected, skipping system dependencies");
            }
        }
        _ => {}
    }

    Ok(())
}

fn install_binary(platform: &PlatformInfo, version: &str, args: &Args) -> Result<()> {
    let install_dir = get_install_dir(args);
    fs::create_dir_all(&install_dir)?;

    let asset_name = platform.asset_name(version);
    let download_url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        GITHUB_REPO, version, asset_name
    );

    println!("Downloading hyntel {} from {}", version, download_url);

    let client = Client::builder().user_agent("hyntel-installer").build()?;
    let response = client.get(&download_url).send()?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to download: HTTP {}", response.status()));
    }

    let bytes = response.bytes()?;
    let temp_dir = env::temp_dir().join(format!("hyntel-install-{}", version));
    fs::create_dir_all(&temp_dir)?;

    let archive_path = temp_dir.join(if cfg!(target_os = "windows") { "hyntel.zip" } else { "hyntel.tar.gz" });
    fs::write(&archive_path, &bytes)?;

    // Extract
    if cfg!(target_os = "windows") {
        extract_zip(&archive_path, &temp_dir)?;
    } else {
        extract_tar_gz(&archive_path, &temp_dir)?;
    }

    // Find and copy binary
    let binary_name = platform.binary_name();
    let extracted_binary = find_binary(&temp_dir, binary_name)?;
    let dest = get_install_dir(args).join(platform.binary_name());

    fs::copy(&extracted_binary, &dest)?;
    
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms)?;
    }

    // Add to PATH if user install
    if matches!(InstallTarget::User, InstallTarget::User) {
        add_to_path(&install_dir)?;
    }

    println!("Installed to {}", dest.display());
    Ok(())
}

fn install_from_source(version: &str, _args: &Args) -> Result<()> {
    println!("Building hyntel {} from source...", version);

    // Check for Rust
    if !command_exists("cargo") {
        println!("Rust toolchain not found. Installing via rustup...");
        install_rustup()?;
    }

    let temp_dir = env::temp_dir().join(format!("hyntel-build-{}", version));
    fs::create_dir_all(&temp_dir)?;

    // Clone and build
    let repo_url = format!("https://github.com/{}.git", GITHUB_REPO);
    run_cmd("git", &["clone", "--branch", &format!("v{}", version), "--depth", "1", &repo_url, temp_dir.to_str().unwrap()], true)?;

    run_cmd("cargo", &["build", "--release", "--workspace"], true)?;

    // Copy binaries
    let install_dir = get_install_dir(&Args {
        prefix: None,
        target: InstallTarget::User,
        ..Default::default()
    });
    fs::create_dir_all(&install_dir)?;

    for binary in ["hyntel", "hyntel-cli", "hyntel-tui", "hyntel-gui"] {
        let src = env::current_dir()?.join("target").join("release").join(binary);
        if src.exists() {
            let dest = get_install_dir(&Args {
                prefix: None,
                target: InstallTarget::User,
                ..Default::default()
            }).join(binary);
            fs::copy(&src, &dest)?;
        }
    }

    println!("Built and installed from source");
    Ok(())
}

fn install_rustup() -> Result<()> {
    if cfg!(target_os = "windows") {
        let script = r#"powershell -Command "& {Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile 'rustup-init.exe'; .\rustup-init.exe -y}"#;
        run_cmd("powershell", &["-Command", script], true)?;
    } else {
        run_cmd("curl", &["--proto", "=https", "--tlsv1.2", "-sSf", "https://sh.rustup.rs", "|", "sh", "-s", "--", "-y"], true)?;
    }
    println!("Rust toolchain installed. Please restart your shell or run 'source ~/.cargo/env'.");
    Ok(())
}

fn create_shortcuts(args: &Args) -> Result<()> {
    let install_dir = get_install_dir(args);
    let binary = install_dir.join(if cfg!(target_os = "windows") { "hyntel.exe" } else { "hyntel" });

    #[cfg(target_os = "linux")]
    {
        // Create .desktop file
        let desktop_dir = dirs::home_dir().unwrap().join(".local/share/applications");
        fs::create_dir_all(&desktop_dir)?;

        let desktop_content = format!(
            r#"[Desktop Entry]
Name=HYNTEL Security Audit
Comment=Cross-platform security audit tool
Exec={}
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
StartupNotify=false
"#,
            binary.display()
        );

        let desktop_path = dirs::home_dir().unwrap().join(".local/share/applications/hyntel.desktop");
        fs::write(&desktop_path, desktop_content)?;
        println!("Created desktop entry: {}", desktop_path.display());
    }

    #[cfg(target_os = "macos")]
    {
        // Create .app bundle or symlink in Applications
        let apps_dir = Path::new("/Applications");
        if apps_dir.exists() {
            let link = apps_dir.join("HYNTEL Security Audit");
            if !link.exists() {
                std::os::unix::fs::symlink(&binary, &link)?;
                println!("Created symlink in Applications");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Create Start Menu shortcut via PowerShell
        let script = format!(
            r#"$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\HYNTEL Security Audit.lnk")
$Shortcut.TargetPath = "{}"
$Shortcut.Description = "HYNTEL Security Audit Tool"
$Shortcut.Save()"#,
            binary.display()
        );

        run_cmd("powershell", &["-Command", &script], false)?;
        println!("Created Start Menu shortcut");
    }

    Ok(())
}

fn add_to_path(install_dir: &Path) -> Result<()> {
    let path_str = install_dir.to_string_lossy();

    #[cfg(not(target_os = "windows"))]
    {
        let shell_rc = if env::var("SHELL").unwrap_or_default().contains("zsh") {
            ".zshrc"
        } else {
            ".bashrc"
        };

        let rc_path = dirs::home_dir().unwrap().join(shell_rc);
        let path_export = format!("\nexport PATH=\"$PATH:{}\"\n", path_str);

        if let Ok(content) = fs::read_to_string(&rc_path) {
            if !content.contains(&*path_str) {
                fs::write(&rc_path, content + &path_export)?;
                println!("Added {} to PATH in {}", install_dir.display(), shell_rc);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to add to user PATH
        let script = format!(
            r#"$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*{}*") {{
    [Environment]::SetEnvironmentVariable("PATH", $currentPath + ";{}", "User")
}}"#,
            install_dir.display(),
            path_str
        );
        run_cmd("powershell", &["-Command", &script], false)?;
    }

    Ok(())
}

fn uninstall(args: &Args) -> Result<()> {
    println!("Uninstalling hyntel...");

    let install_dir = get_install_dir(args);
    let binary = install_dir.join(if cfg!(target_os = "windows") { "hyntel.exe" } else { "hyntel" });

    if binary.exists() {
        fs::remove_file(&binary)?;
        println!("Removed binary: {}", binary.display());
    }

    // Remove desktop entry
    #[cfg(target_os = "linux")]
    {
        let desktop_path = dirs::home_dir().unwrap().join(".local/share/applications/hyntel.desktop");
        if desktop_path.exists() {
            fs::remove_file(&desktop_path)?;
        }
    }

    #[cfg(target_os = "macos")]
    {
        let link = Path::new("/Applications/HYNTEL Security Audit");
        if link.exists() {
            fs::remove_file(&link)?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        let shortcut = dirs::home_dir().unwrap().join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/HYNTEL Security Audit.lnk");
        if shortcut.exists() {
            fs::remove_file(&shortcut)?;
        }
    }

    println!("Uninstall complete.");
    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str], verbose: bool) -> Result<()> {
    let mut cmd_obj = Command::new(cmd);
    cmd_obj.args(args);
    cmd_obj.stdout(Stdio::inherit());
    cmd_obj.stderr(Stdio::inherit());

    if verbose {
        println!("Running: {} {}", cmd, args.join(" "));
    }

    let status = cmd_obj.status()?;
    if !status.success() {
        return Err(anyhow!("Command failed: {} {}", cmd, args.join(" ")));
    }
    Ok(())
}

fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn find_binary(dir: &Path, name: &str) -> Result<PathBuf> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_name() == name && entry.file_type().is_file() {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(anyhow!("Binary {} not found in {}", name, dir.display()))
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive)?;
    let tar = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(dest)?;
    Ok(())
}

fn extract_zip(archive: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive)?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(dest)?;
    Ok(())
}

fn print_post_install_info(args: &Args) {
    let install_dir = get_install_dir(args);
    println!("\nInstallation complete!");
    println!("Binary installed to: {}", install_dir.display());
    println!("Run 'hyntel --help' to get started");

    #[cfg(not(target_os = "windows"))]
    {
        println!("\nNote: You may need to restart your shell or run 'source ~/.bashrc' for PATH changes to take effect.");
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            from_source: false,
            version: None,
            prefix: None,
            skip_deps: false,
            force: false,
            uninstall: false,
            dry_run: false,
            verbose: false,
            target: InstallTarget::User,
        }
    }
}