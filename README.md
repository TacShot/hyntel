# hyntel - Cross-platform Security Audit Tool

Cross-platform security audit tool rewritten in Rust. Maintains feature parity with the original Python/PowerShell implementation while adding performance, type safety, and a modern architecture.

## Features

### Core Security Auditing
- **Cross-platform**: Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (x86_64)
- **Security checks**: 
  - Linux: Firewall (ufw/firewalld/nftables), SSH (root login, password auth), Auto-updates (unattended-upgrades/dnf-automatic)
  - macOS: Firewall, FileVault, Remote Login, Auto-updates
  - Windows: Firewall profiles, BitLocker, Remote Desktop, Defender real-time, Driver signing
- **CVE enrichment**: NIST NVD API 2.0 integration with CVSS scoring & EPSS
- **Application inventory**: dpkg/rpm/pacman/brew/Windows Registry + CPE matching
- **Process assessment**: Suspicious process detection (temp dirs, injection signs, known tool names)
- **Remediation scripts**: Platform-specific (bash/PowerShell) with safety guards
- **Multiple outputs**: Text, JSON, CSV
- **Three interfaces**: CLI, TUI (ratatui/crossterm), GUI (egui/eframe)
- **Compliance mapping**: ISO27001, HIPAA, PCI-DSS
- **Desktop report export**: Automatic bundle to ~/Desktop

### Net-Installer (hyntel-installer)
- **Cross-platform**: Single binary works on Linux, macOS, Windows
- **Multiple install modes**: Pre-built binary (default) or `--from-source`
- **Version pinning**: `--version` to install specific releases
- **Target selection**: `--target user|system` (user=~/.local/bin, system=/usr/local/bin or C:\Program Files\hyntel)
- **Auto-dependencies**: apt/dnf/pacman/brew/winget/choco/scoop
- **Shortcut creation**: .desktop (Linux), symlink (macOS), Start Menu (Windows)
- **PATH management**: Auto-adds to shell rc files / Windows user PATH
- **Uninstall**: `--uninstall` removes binaries, shortcuts, PATH entries

## Architecture

```
hyntel-rs/
├── hyntel-core/      # Core audit engine (library)
│   ├── models.rs          # Data structures (Platform, AuditRule, CheckResult, etc.)
│   ├── command_runner.rs  # Safe command execution
│   ├── platform.rs        # OS detection & info gathering
│   ├── checks.rs          # Platform-specific security checks (27 checks total)
│   ├── nvd.rs             # NIST NVD API 2.0 client with CVSS/EPSS
│   ├── inventory.rs       # Application & process inventory
│   ├── ad.rs              # Active Directory security scanning
│   ├── logs.rs            # System log collection & filtering
│   ├── remediation.rs     # Script generation (bash/PowerShell)
│   ├── reporting.rs       # Text/JSON/CSV rendering
│   └── audit.rs           # Orchestration engine
├── hyntel-cli/      # Command-line interface
│   └── main.rs         # Interactive prompts + non-interactive flags
├── hyntel-tui/      # Terminal UI (ratatui/crossterm)
│   └── main.rs         # Grid menus, config wizard, results browser
├── hyntel-gui/      # Graphical UI (egui/eframe)
│   └── main.rs         # 7 tabs: Summary, Findings, Apps, Processes, Remediation, Logs, AD
├── hyntel/          # Main binary (routes to CLI/TUI/GUI)
└── installer/       # Net-installer (Rust + Shell + PowerShell)
    ├── src/main.rs    # Rust installer binary
    ├── install.sh     # Bash installer (Linux/macOS)
    ├── install.ps1    # PowerShell installer (Windows)
    └── Cargo.toml
```

### Design Principles
- **Modularity**: Core library (`hyntel-core`) is UI-agnostic; all interfaces use it as a library
- **Type Safety**: Strong Rust types for all audit data (Platform, CheckResult, Severity, etc.)
- **Cross-Platform Abstraction**: Platform-specific logic isolated in `platform.rs`, `checks.rs`, `ad.rs`, `logs.rs`
- **Memory Safety**: Zero `unsafe` in core; only FFI in platform-specific modules
- **Async-Free Core**: Synchronous core for simplicity; async only in installer HTTP downloads

## Resource Usage

| Component | Binary Size (Release) | Typical RAM | CPU (Idle) | CPU (Scanning) |
|-----------|----------------------|-------------|------------|----------------|
| hyntel-cli | ~3.7 MB | 5-10 MB | <1% | 10-30% (1 core) |
| hyntel-tui | ~3.6 MB | 8-15 MB | <1% | 10-30% (1 core) |
| hyntel-gui | ~6.9 MB | 30-80 MB | <1% | 15-40% (1-2 cores) |
| hyntel-installer | ~3.4 MB | 5-10 MB | <1% | 5-20% (download) |
| **Total (all)** | **~17.6 MB** | - | - | - |

### Disk Usage
- **Installation**: ~20 MB (all binaries + installers)
- **Portable zip**: ~9 MB (compressed)
- **Runtime artifacts**: ~1-5 MB per scan (text/JSON/CSV reports)

### Network
- **NVD API**: ~50-200 KB per scan (CVE lookups, cached)
- **Installer download**: ~3-7 MB per binary (compressed)
- **Git clone (from-source)**: ~50-100 MB

## Feature List

### Security Checks (27 Total)

| Platform | Check | Severity | Standard |
|----------|-------|----------|----------|
| Linux | Firewall enabled | High | ISO27001, HIPAA, PCI_DSS |
| Linux | SSH root login disabled | Critical | ISO27001, HIPAA, PCI_DSS |
| Linux | SSH password auth disabled | High | ISO27001, HIPAA, PCI_DSS |
| Linux | Auto-updates enabled | High | ISO27001, HIPAA, PCI_DSS |
| macOS | Firewall enabled | High | ISO27001, HIPAA, PCI_DSS |
| macOS | FileVault enabled | Critical | ISO27001, HIPAA, PCI_DSS |
| macOS | Remote Login disabled | Critical | ISO27001, HIPAA, PCI_DSS |
| macOS | Auto-updates enabled | High | ISO27001, HIPAA, PCI_DSS |
| Windows | Firewall profiles enabled | High | ISO27001, HIPAA, PCI_DSS |
| Windows | BitLocker enabled | High | ISO27001, HIPAA, PCI_DSS |
| Windows | Remote Desktop disabled | Critical | ISO27001, HIPAA, PCI_DSS |
| Windows | Defender real-time enabled | High | ISO27001, HIPAA, PCI_DSS |
| Windows | Driver signing verification | Critical | ISO27001, HIPAA, PCI_DSS |

### Additional Capabilities
- **CVE Enrichment**: NIST NVD API 2.0 with CVSS v3.1/v3.0/v2 scoring, EPSS exploitability
- **Application Inventory**: dpkg/rpm/pacman/brew/Windows Registry + CPE matching
- **Process Assessment**: Temp dir execution, injection signs, known tool detection (mimikatz, netcat, etc.)
- **System Logs**: Linux (journalctl, auth.log), macOS (log show, system.log), Windows (Security, System event logs)
- **AD Scanning**: LDAP signing, SMB signing, SMBv1, share perms, privileged users, SSSD config
- **Compliance**: ISO27001, HIPAA, PCI_DSS tagging per check
- **Output Formats**: Human-readable text, JSON (machine), CSV (spreadsheet)

### Interfaces
| Interface | Launch | Best For |
|-----------|--------|----------|
| CLI | `hyntel run --interactive` | Automation, CI/CD, scripting |
| TUI | `hyntel tui` | Interactive exploration, servers |
| GUI | `hyntel gui` | Visual analysis, desktop users |

### Installer Options
| Flag | Description |
|------|-------------|
| `--from-source` | Build from source instead of downloading pre-built binary |
| `--version VERSION` | Install specific version (default: latest) |
| `--prefix PATH` | Install to custom directory |
| `--skip-deps` | Skip system dependency installation |
| `--force` | Force reinstall even if already installed |
| `--dry-run` | Show what would be done without installing |
| `--verbose` | Verbose output |
| `--target user\|system` | Installation target (default: user) |
| `--uninstall` | Uninstall hyntel |

## Requirements

### Runtime
| Platform | Minimum Version | Dependencies |
|----------|----------------|--------------|
| Linux | glibc 2.31+ | glibc, libgcc, libstdc++ |
| macOS | 11.0 (Big Sur)+ | System libraries |
| Windows | Windows 10 1909+ | Universal CRT |

### Build (from source)
| Tool | Minimum Version |
|------|----------------|
| Rust | 1.75+ (MSRV) |
| Cargo | Included with Rust |
| Git | Any recent version |

### Build Dependencies (Linux)
```bash
# Ubuntu/Debian
apt install -y pkg-config libssl-dev libudev-dev libgtk-3-dev libwebkit2gtk-4.0-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora/RHEL
dnf install -y pkgconfig openssl-devel libudev-devel gtk3-devel webkit2gtk4.0-devel librsvg2-devel

# Arch
pacman -S pkgconf openssl libudev gtk3 webkit2gtk librsvg
```

### Build Dependencies (macOS)
```bash
# Xcode Command Line Tools required
xcode-select --install
# Optional: Homebrew for additional deps
brew install pkg-config openssl
```

### Build Dependencies (Windows)
```powershell
# Visual Studio 2022 with C++ workload OR Build Tools
# Windows SDK 10.0.19041+
# Rust via rustup
```

## Quick Start

### Install via Net-Installer (Recommended)
```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex

# Specific version from source
curl ... | bash -s -- --from-source --version 0.1.0

# System-wide (Linux/macOS)
curl ... | sudo bash -s -- --target system
```

### Run
```bash
# CLI - Interactive
hyntel run --interactive

# CLI - Automated
hyntel run --target-os auto --include-cves --generate-remediation --format json

# TUI (interactive terminal UI)
hyntel tui

# GUI (desktop)
hyntel gui

# Help
hyntel --help
hyntel run --help
```

### Run Tests
```bash
cargo test --workspace
```

### Development
```bash
# Format
cargo fmt --all -- --check

# Lint
cargo clippy --workspace -- -D warnings

# Build all
cargo build --release --workspace
```

## License
MIT OR Apache-2.0