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
  "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' >/dev/null 2>&1
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

install_python_linux() {
  if resolve_python >/dev/null 2>&1; then
    log "Python 3 already installed"
    return
  fi

  if has_command apt-get; then
    log "Installing Python with apt"
    require_sudo apt-get update
    require_sudo apt-get install -y python3 python3-pip python3-venv
    return
  fi

  if has_command pacman; then
    log "Installing Python with pacman"
    require_sudo pacman -Sy --noconfirm python python-pip
    return
  fi

  echo "No supported Linux package manager found. Expected apt-get or pacman." >&2
  exit 1
}

install_python_macos() {
  if resolve_python >/dev/null 2>&1; then
    log "Python 3 already installed"
    return
  fi

  if ! has_command brew; then
    echo "Homebrew is required on macOS. Install it first from https://brew.sh/" >&2
    exit 1
  fi

  log "Installing Python with Homebrew"
  brew install python
}

ensure_pip() {
  local python_cmd="$1"
  if "$python_cmd" -m pip --version >/dev/null 2>&1; then
    return
  fi
  log "Bootstrapping pip"
  "$python_cmd" -m ensurepip --upgrade
}

setup_virtualenv() {
  local python_cmd="$1"
  log "Creating virtual environment in ${ROOT_DIR}/.venv"
  "$python_cmd" -m venv "${ROOT_DIR}/.venv"
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
    exit 1
  }

  ensure_pip "$python_cmd"
  setup_virtualenv "$python_cmd"

  log "Setup complete"
  log "Activate with: source ${ROOT_DIR}/.venv/bin/activate"
  log "Run with: security-audit --help"
}

main "$@"
