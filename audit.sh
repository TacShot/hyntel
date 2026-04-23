#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN_DIR="${ROOT_DIR}/.venv/bin"
PYTHON_BIN="${VENV_BIN_DIR}/python"

log() {
  printf '[audit] %s\n' "$1"
}

ensure_ready() {
  if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "Virtual environment not found at ${PYTHON_BIN}." >&2
    echo "Run ./setup.sh first." >&2
    exit 1
  fi
}

run_terminal_interface() {
  log "Launching the terminal interface"
  exec "${PYTHON_BIN}" -m security_audit_tool.terminal_ui
}

run_gui() {
  log "Launching the GUI"
  exec "${PYTHON_BIN}" -m security_audit_tool.launcher
}

print_menu() {
  cat <<'EOF'

Choose an option:
  1) Use Terminal interface
  2) Launch GUI
  3) Exit

EOF
}

run_selection() {
  case "${1}" in
    1)
      run_terminal_interface
      ;;
    2)
      run_gui
      ;;
    3|0|exit)
      log "Exiting"
      exit 0
      ;;
    *)
      echo "Invalid selection: ${1}" >&2
      ;;
  esac
}

interactive_menu() {
  local selection
  while true; do
    print_menu
    read -r -p "Enter option number: " selection
    run_selection "${selection}"
  done
}

main() {
  ensure_ready

  case "${1:-}" in
    --gui|gui|2)
      run_gui
      ;;
    --tui|tui|1)
      run_terminal_interface
      ;;
    3|0|exit)
      log "Exiting"
      exit 0
      ;;
    "")
      interactive_menu
      ;;
    *)
      run_selection "$1"
      ;;
  esac
}

main "$@"
