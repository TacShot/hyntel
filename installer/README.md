# hyntel-installer

Cross-platform net-installer for the **hyntel security audit tool**.

## Quick Install

### Linux/macOS (Bash)

```bash
# Install latest version
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash

# Install specific version from source
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --from-source --version 0.1.0

# Install system-wide (requires sudo)
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | sudo bash -s -- --target system

# Uninstall
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --uninstall
```

### Windows (PowerShell)

```powershell
# Install latest version
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex

# Install specific version from source
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --from-source --version 0.1.0

# Install system-wide (requires admin)
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --target system

# Uninstall
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --uninstall
```

### Via Cargo (if you have Rust)

```bash
# Install pre-built binary via cargo-binstall
cargo binstall hyntel

# Or build from source
cargo install --git https://github.com/TacShot/hyntel --locked
```

## Features

- **Cross-platform**: Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (x86_64)
- **Zero dependencies**: Downloads pre-built binaries by default
- **From source option**: `--from-source` builds from source with Cargo
- **System dependencies**: Auto-installs required packages (apt/dnf/pacman/brew/winget)
- **Multiple targets**: User (`~/.local/bin`) or system (`/usr/local/bin` or `C:\Program Files\hyntel`)
- **Auto shortcuts**: Creates desktop entries (Linux), symlinks (macOS), Start Menu shortcuts (Windows)
- **PATH management**: Automatically adds to PATH
- **Version pinning**: Install specific versions with `--version`
- **From-source builds**: `--from-source` for custom builds
- **Uninstall support**: `--uninstall` removes all traces

## Installer Options

| Option | Description |
|--------|-------------|
| `--from-source` | Build from source instead of downloading pre-built binary |
| `--version VERSION` | Install specific version (default: latest) |
| `--prefix PATH` | Install to custom directory |
| `--skip-deps` | Skip system dependency installation |
| `--force` | Force reinstall even if already installed |
| `--dry-run` | Show what would be done without installing |
| `--verbose` | Verbose output |
| `--target TARGET` | Installation target: `user` (default) or `system` |
| `--uninstall` | Uninstall hyntel |

## Supported Platforms

| OS | Architectures | Package Manager |
|----|---------------|-----------------|
| Linux | x86_64, aarch64 | apt, dnf, pacman |
| macOS | x86_64, arm64 | Homebrew |
| Windows | x86_64 | winget, choco, scoop |

## System Dependencies

The installer automatically installs required system dependencies:

**Linux:**
- `pkg-config`, `libssl-dev`, `libudev-dev`
- `libgtk-3-dev`, `libwebkit2gtk-4.0-dev`
- `libayatana-appindicator3-dev`, `librsvg2-dev`

**macOS:** None required (uses Homebrew if available)

**Windows:** None required (uses winget/choco/scoop if available)

## Building the Installer

```bash
cd installer
cargo build --release
```

The installer binary will be at `target/release/hyntel-installer`.

## Creating a Release

1. Build binaries for all platforms:
```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Linux aarch64
cargo build --release --target aarch64-unknown-linux-gnu

# macOS x86_64
cargo build --release --target x86_64-apple-darwin

# macOS arm64
cargo build --release --target aarch64-apple-darwin

# Windows x86_64
cargo build --release --target x86_64-pc-windows-msvc
```

2. Create archives:
```bash
# Linux/macOS
tar -czf hyntel-<platform>-<version>.tar.gz hyntel hyntel-cli hyntel-tui hyntel-gui

# Windows
zip hyntel-windows-<version>.zip hyntel.exe hyntel-cli.exe hyntel-tui.exe hyntel-gui.exe
```

3. Upload to GitHub Releases with tag `v<version>`

## Uninstall

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --uninstall

# Windows
iwr -useb https://raw.githubusercontent.com/TacShot/hyntel/main/install.ps1 | iex -- --uninstall
```

## License

MIT OR Apache-2.0