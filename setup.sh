#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '[setup] %s\n' "$1"
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

is_python3_command() {
  local candidate="$1"
  if ! has_command "$candidate"; then
    return 1
  fi
  "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' >/dev/null 2>&1 || return 1
  return 0
}

resolve_python() {
  if is_python3_command python3; then
    echo "python3"
    return
  fi
  if is_python3_command python; then
    echo "python"
    return
  fi
  return 1
}

require_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

detect_os() {
  local uname_out
  uname_out="$(uname -s)"
  case "${uname_out}" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    *)
      echo "Unsupported operating system: ${uname_out}" >&2
      exit 1
      ;;
  esac
}

python_has_module() {
  local python_cmd="$1"
  local module_name="$2"
  "$python_cmd" -c "import ${module_name}" >/dev/null 2>&1
}

install_python_linux() {
  if resolve_python >/dev/null 2>&1; then
    log "Python 3 already installed"
  elif has_command apt-get; then
    log "Installing Python with apt"
    require_sudo apt-get update
    require_sudo apt-get install -y python3 python3-pip python3-venv
    # Refresh PATH in case Python was installed in a new location
    export PATH="/usr/bin:/usr/local/bin:$PATH"
    return
  elif has_command pacman; then
    log "Installing Python with pacman"
    require_sudo pacman -Sy --noconfirm python python-pip
    # Refresh PATH in case Python was installed in a new location
    export PATH="/usr/bin:/usr/local/bin:$PATH"
    return
  else
    echo "No supported Linux package manager found. Expected apt-get or pacman." >&2
    echo "Please install Python 3 manually and ensure it's in your PATH." >&2
    exit 1
  fi

  if has_command apt-get; then
    local python_cmd
    python_cmd="$(resolve_python)"
    if [[ -z "$python_cmd" ]]; then
      echo "Python 3 installation failed. Please install Python 3 manually." >&2
      exit 1
    fi
    if ! python_has_module "$python_cmd" venv; then
      log "Installing missing venv support with apt"
      require_sudo apt-get update
      require_sudo apt-get install -y python3-venv python3-pip
    fi
    return
  fi

  if has_command pacman; then
    local python_cmd
    python_cmd="$(resolve_python)"
    if [[ -z "$python_cmd" ]]; then
      echo "Python 3 installation failed. Please install Python 3 manually." >&2
      exit 1
    fi
    if ! python_has_module "$python_cmd" venv; then
      log "Refreshing Python packages with pacman to restore venv support"
      require_sudo pacman -Sy --noconfirm python python-pip
    fi
    return
  fi
}

install_python_macos() {
  if resolve_python >/dev/null 2>&1; then
    log "Python 3 already installed"
    return
  fi

  if ! has_command brew; then
    echo "Homebrew is required on macOS. Install it first from https://brew.sh/" >&2
    echo "Alternatively, install Python 3 manually from https://www.python.org/downloads/" >&2
    exit 1
  fi

  log "Installing Python with Homebrew"
  if ! brew install python; then
    echo "Failed to install Python with Homebrew." >&2
    echo "Please install Python 3 manually from https://www.python.org/downloads/" >&2
    exit 1
  fi

  # Refresh PATH to include Homebrew-installed Python
  export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

  # Verify Python installation
  if ! resolve_python >/dev/null 2>&1; then
    echo "Python installation completed but could not be found in PATH." >&2
    echo "Please add Homebrew to your PATH and run this script again." >&2
    exit 1
  fi
}

ensure_pip() {
  local python_cmd="$1"
  if "$python_cmd" -m pip --version >/dev/null 2>&1; then
    return
  fi
  log "Bootstrapping pip"
  if "$python_cmd" -m ensurepip --upgrade >/dev/null 2>&1; then
    return
  fi

  if [[ "$(detect_os)" == "linux" ]] && has_command apt-get; then
    log "Installing pip with apt"
    require_sudo apt-get update
    require_sudo apt-get install -y python3-pip python3-venv
    return
  fi

  if [[ "$(detect_os)" == "linux" ]] && has_command pacman; then
    log "Installing pip with pacman"
    require_sudo pacman -Sy --noconfirm python-pip
    return
  fi

  echo "Could not bootstrap pip for the detected Python 3 interpreter." >&2
  exit 1
}

setup_virtualenv() {
  local python_cmd="$1"
  log "Creating virtual environment in ${ROOT_DIR}/.venv"
  if ! "$python_cmd" -m venv "${ROOT_DIR}/.venv"; then
    echo "Failed to create the virtual environment. Make sure Python 3 includes the venv module." >&2
    exit 1
  fi
  if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    echo "Virtual environment creation did not produce ${ROOT_DIR}/.venv/bin/python." >&2
    echo "On Debian/Ubuntu, install python3-venv and rerun ./setup.sh." >&2
    exit 1
  fi
  log "Installing project in editable mode"
  "${ROOT_DIR}/.venv/bin/python" -m pip install --upgrade pip
  "${ROOT_DIR}/.venv/bin/python" -m pip install -e "${ROOT_DIR}"
}

main() {
  case "$(detect_os)" in
    linux)
      install_python_linux
      ;;
    macos)
      install_python_macos
      ;;
  esac

  python_cmd="$(resolve_python)" || {
    echo "A Python 3 interpreter could not be found after installation." >&2
    echo "Please install Python 3 manually and ensure it's in your PATH." >&2
    echo "Download from: https://www.python.org/downloads/" >&2
    exit 1
  }

  ensure_pip "$python_cmd"
  setup_virtualenv "$python_cmd"

  log "Setup complete"
  log "Run audits with: ./audit.sh"
  log "Launch GUI with: ./audit.sh --gui"
  log ""
  log "To use the 'security-audit' CLI directly, activate the virtual environment first:"
  log "  source .venv/bin/activate"
  log "  security-audit --help"
  log ""
  log "Or invoke it without activation using its full path:"
  log "  ./.venv/bin/security-audit --help"
}

main "$@"
