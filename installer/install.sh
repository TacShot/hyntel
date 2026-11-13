#!/bin/bash
# hyntel net-installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash
#        curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --from-source
#        curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --version 0.1.0

set -euo pipefail

REPO="TacShot/hyntel"
BINARY="hyntel"
INSTALLER_VERSION="0.1.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_help() {
    cat << EOF
hyntel-installer v${INSTALLER_VERSION}
Cross-platform net-installer for hyntel security audit tool

Usage: $0 [OPTIONS]

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
    -h, --help          Show this help

Examples:
    # Install latest version for current user
    curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash

    # Install specific version from source
    curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --from-source --version 0.1.0

    # Install system-wide (requires sudo)
    curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | sudo bash -s -- --target system

    # Uninstall
    curl -fsSL https://raw.githubusercontent.com/TacShot/hyntel/main/install.sh | bash -s -- --uninstall
EOF
}

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Default options
FROM_SOURCE=false
VERSION=""
PREFIX=""
SKIP_DEPS=false
FORCE=false
DRY_RUN=false
VERBOSE=false
TARGET="user"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --from-source)
            FROM_SOURCE=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --uninstall)
            uninstall
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            if [[ "$ARCH" == "x86_64" ]]; then
                ASSET_PATTERN="hyntel-x86_64-unknown-linux-gnu"
            elif [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
                ASSET_PATTERN="hyntel-aarch64-unknown-linux-gnu"
            else
                log_error "Unsupported architecture: $ARCH"
                exit 1
            fi
            ;;
        darwin)
            if [[ "$ARCH" == "x86_64" ]]; then
                ASSET_PATTERN="hyntel-x86_64-apple-darwin"
            elif [[ "$ARCH" == "arm64" ]]; then
                ASSET_PATTERN="hyntel-aarch64-apple-darwin"
            else
                log_error "Unsupported architecture: $ARCH"
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    BINARY_NAME="hyntel"
    if [[ "$OS" == "windows" ]]; then
        BINARY_NAME="hyntel.exe"
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        PKG_MGR="apt"
        INSTALL_CMD="apt install -y"
        DEPS="pkg-config libssl-dev libudev-dev libgtk-3-dev libwebkit2gtk-4.0-dev libayatana-appindicator3-dev librsvg2-dev"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
        INSTALL_CMD="dnf install -y"
        DEPS="pkgconfig openssl-devel libudev-devel gtk3-devel webkit2gtk4.0-devel librsvg2-devel"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
        INSTALL_CMD="pacman -S --needed --noconfirm"
        DEPS="pkgconf openssl libudev gtk3 webkit2gtk librsvg"
    elif command -v brew >/dev/null 2>&1; then
        PKG_MGR="brew"
        INSTALL_CMD="brew install"
        DEPS=""
    else
        PKG_MGR="none"
        log_warn "No supported package manager found, skipping system dependencies"
    fi
}

# Fetch latest version from GitHub
fetch_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    local version
    version=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "$url" | grep '"tag_name"' | sed -E 's/.*"tag_name": "v?([^"]+)".*/\1/')
    echo "$version"
}

# Download and install binary
install_binary() {
    local version="$1"
    local asset_name="${ASSET_PATTERN}-${version}"
    local ext="tar.gz"

    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        ext="zip"
    fi

    asset_name="${asset_name}-${version}.${ext}"
    download_url="https://github.com/${REPO}/releases/download/v${version}/${asset_name}"

    log_info "Downloading ${BINARY} ${version} from ${download_url}"

    local temp_dir
    temp_dir=$(mktemp -d -t hyntel-install-XXXXXX)
    local archive_path="${temp_dir}/${asset_name}"

    if ! curl -fsSL -L -o "${archive_path}" "${download_url}"; then
        log_error "Failed to download from ${download_url}"
        return 1
    fi

    # Extract
    if [[ "$ext" == "zip" ]]; then
        unzip -q "${archive_path}" -d "${temp_dir}"
    else
        tar -xzf "${archive_path}" -C "${temp_dir}"
    fi

    # Find and install binary
    local binary_path
    binary_path=$(find "${temp_dir}" -name "${BINARY_NAME}" -type f | head -n1)

    if [[ -z "${binary_path}" ]]; then
        log_error "Binary not found in archive"
        return 1
    fi

    local install_dir
    install_dir=$(get_install_dir)
    mkdir -p "${install_dir}"

    cp "${binary_path}" "${install_dir}/${BINARY_NAME}"
    chmod +x "${install_dir}/${BINARY_NAME}"

    log_success "Installed to ${install_dir}/${BINARY_NAME}"
}

# Build from source
install_from_source() {
    local version="$1"

    log_info "Building hyntel ${version} from source..."

    if ! command -v cargo >/dev/null 2>&1; then
        log_info "Rust toolchain not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    local temp_dir
    temp_dir=$(mktemp -d -t hyntel-build-XXXXXX)

    git clone --branch "v${version}" --depth 1 "https://github.com/${REPO}.git" "${temp_dir}"
    cd "${temp_dir}"
    cargo build --release --workspace

    local install_dir
    install_dir=$(get_install_dir)
    mkdir -p "${install_dir}"

    for binary in hyntel hyntel-cli hyntel-tui hyntel-gui; do
        local src="target/release/${binary}"
        if [[ -f "${src}" ]]; then
            cp "${src}" "${install_dir}/${binary}"
            chmod +x "${install_dir}/${binary}"
        fi
    done

    log_success "Built and installed from source"
}

get_install_dir() {
    if [[ -n "${PREFIX}" ]]; then
        echo "${PREFIX}"
        return
    fi

    if [[ "${TARGET}" == "system" ]]; then
        if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
            echo "/c/Program Files/hyntel"
        else
            echo "/usr/local/bin"
        fi
    else
        echo "${HOME}/.local/bin"
    fi
}

# Check if already installed
is_installed() {
    local install_dir
    install_dir=$(get_install_dir)
    [[ -f "${install_dir}/${BINARY_NAME}" ]]
}

# Create desktop entries/shortcuts
create_shortcuts() {
    local install_dir
    install_dir=$(get_install_dir)
    local binary="${install_dir}/${BINARY_NAME}"

    case "$OSTYPE" in
        linux*)
            local desktop_dir="${HOME}/.local/share/applications"
            mkdir -p "${desktop_dir}"

            cat > "${desktop_dir}/hyntel.desktop" << EOF
[Desktop Entry]
Name=HYNTEL Security Audit
Comment=Cross-platform security audit tool
Exec=${binary}
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
StartupNotify=false
EOF
            log_info "Created desktop entry: ${desktop_dir}/hyntel.desktop"
            ;;
        darwin*)
            if [[ -d "/Applications" ]]; then
                ln -sf "${binary}" "/Applications/HYNTEL Security Audit"
                log_info "Created symlink in Applications"
            fi
            ;;
    esac
}

# Add to PATH
add_to_path() {
    local install_dir
    install_dir=$(get_install_dir)

    case "$OSTYPE" in
        linux*|darwin*)
            local shell_rc
            if [[ -n "${ZSH_VERSION:-}" ]]; then
                shell_rc=".zshrc"
            else
                shell_rc=".bashrc"
            fi

            local rc_path="${HOME}/${shell_rc}"
            local path_export="export PATH=\"\$PATH:${install_dir}\""

            if [[ -f "${rc_path}" ]] && ! grep -q "${install_dir}" "${rc_path}"; then
                echo -e "\n${path_export}" >> "${rc_path}"
                log_info "Added ${install_dir} to PATH in ${shell_rc}"
                log_warn "Run 'source ${rc_path}' or restart your shell for changes to take effect"
            fi
            ;;
    esac
}

# Print post-install info
print_post_install_info() {
    local install_dir
    install_dir=$(get_install_dir)

    echo
    log_success "Installation complete!"
    echo "Binary installed to: ${install_dir}"
    echo "Run 'hyntel --help' to get started"

    if [[ "$OSTYPE" != "msys" ]] && [[ "$OSTYPE" != "cygwin" ]] && [[ "$OSTYPE" != "win32" ]]; then
        echo
        log_info "Note: You may need to restart your shell or run 'source ~/.bashrc' for PATH changes to take effect."
    fi
}

# Main
main() {
    echo -e "${BLUE}hyntel-installer v${INSTALLER_VERSION}${NC}"
    echo "Cross-platform net-installer for hyntel security audit tool"
    echo

    detect_platform
    detect_package_manager

    if [[ -z "${VERSION}" ]]; then
        log_info "Fetching latest version..."
        VERSION=$(fetch_latest_version)
        log_info "Latest version: ${VERSION}"
    fi

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY RUN] Would install ${BINARY} ${VERSION} for ${ASSET_PATTERN}"
        exit 0
    fi

    if [[ "${FORCE}" != "true" ]] && is_installed; then
        log_warn "${BINARY} is already installed. Use --force to reinstall."
        exit 0
    fi

    # Install system dependencies
    if [[ "${SKIP_DEPS}" != "true" ]]; then
        log_info "Installing system dependencies..."
        if [[ "${PKG_MGR}" != "none" ]]; then
            eval "${INSTALL_CMD} ${DEPS}"
        fi
    fi

    # Install
    if [[ "${FROM_SOURCE}" == "true" ]]; then
        install_from_source "${VERSION}"
    else
        install_binary "${VERSION}"
    fi

    create_shortcuts
    add_to_path

    print_post_install_info
}

# Handle uninstall
uninstall() {
    log_info "Uninstalling hyntel..."

    local install_dir
    install_dir=$(get_install_dir)
    local binary="${install_dir}/${BINARY_NAME}"

    if [[ -f "${binary}" ]]; then
        rm -f "${binary}"
        log_info "Removed binary: ${binary}"
    fi

    # Remove desktop entry
    case "$OSTYPE" in
        linux*)
            local desktop_path="${HOME}/.local/share/applications/hyntel.desktop"
            if [[ -f "${desktop_path}" ]]; then
                rm -f "${desktop_path}"
            fi
            ;;
        darwin*)
            local link="/Applications/HYNTEL Security Audit"
            if [[ -L "${link}" ]]; then
                rm -f "${link}"
            fi
            ;;
    esac

    log_success "Uninstall complete."
    exit 0
}

main "$@"