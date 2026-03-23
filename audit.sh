#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN_DIR="${ROOT_DIR}/.venv/bin"
PYTHON_BIN="${VENV_BIN_DIR}/python"
CLI_BIN="${VENV_BIN_DIR}/security-audit"

log() {
  printf '[audit] %s\n' "$1"
}

detect_os() {
  local uname_out
  uname_out="$(uname -s)"
  case "${uname_out}" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    *) echo "unknown" ;;
  esac
}

ensure_ready() {
  if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "Virtual environment not found at ${PYTHON_BIN}." >&2
    echo "Run ./setup.sh first." >&2
    exit 1
  fi
}

run_detect_os() {
  local detected_os
  detected_os="$(detect_os)"
  if [[ "${detected_os}" == "unknown" ]]; then
    echo "Unsupported operating system for audit.sh." >&2
    exit 1
  fi
  printf '%s\n' "${detected_os}"
}

run_basic_audit() {
  local detected_os="$1"
  log "Running configuration audit"
  "${CLI_BIN}" --target-os "${detected_os}" --generate-remediation --save-to-desktop
}

run_cve_audit() {
  local detected_os="$1"
  log "Running configuration audit with NVD CVE lookup"
  "${CLI_BIN}" --target-os "${detected_os}" --generate-remediation --save-to-desktop --include-cves
}

run_application_scan() {
  local detected_os="$1"
  log "Running installed application CVE scan"
  "${CLI_BIN}" --target-os "${detected_os}" --generate-remediation --save-to-desktop --scan-apps
}

run_gui() {
  log "Launching GUI"
  exec "${PYTHON_BIN}" -m security_audit_tool.launcher
}

run_full() {
  local detected_os="$1"
  log "Running full audit flow"
  "${CLI_BIN}" \
    --target-os "${detected_os}" \
    --generate-remediation \
    --save-to-desktop \
    --include-cves \
    --scan-apps
}

print_menu() {
  cat <<'EOF'

Choose a step to run:
  1) Detect OS
  2) Run configuration audit and create report
  3) Run configuration audit with CVE lookup
  4) Run installed application CVE scan
  5) Launch GUI
  full) Run the full audit flow
  0) Exit

EOF
}

run_step() {
  local detected_os="$1"
  local selection="$2"

  case "${selection}" in
    1)
      log "Detected OS: ${detected_os}"
      ;;
    2)
      run_basic_audit "${detected_os}"
      ;;
    3)
      run_cve_audit "${detected_os}"
      ;;
    4)
      run_application_scan "${detected_os}"
      ;;
    5)
      run_gui
      ;;
    full)
      run_full "${detected_os}"
      ;;
    0)
      log "Exiting"
      exit 0
      ;;
    *)
      echo "Invalid selection: ${selection}" >&2
      ;;
  esac
}

interactive_menu() {
  local detected_os="$1"
  local selection

  while true; do
    print_menu
    read -r -p "Enter step number (or full): " selection
    run_step "${detected_os}" "${selection}"
  done
}

main() {
  ensure_ready

  local detected_os
  detected_os="$(run_detect_os)"
  log "Detected OS: ${detected_os}"

  if [[ "${1:-}" == "--gui" ]]; then
    shift
    run_gui "$@"
  fi

  if [[ $# -gt 0 ]]; then
    run_step "${detected_os}" "$1"
    exit 0
  fi

  interactive_menu "${detected_os}"
}

main "$@"
