#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# cleanup.sh – Remove audit artifacts, venv, cached files, and Desktop
#              reports so that sensitive details of previously audited
#              machines are not left behind.
#
# Usage:
#   ./cleanup.sh           # Interactive – prompts before each section
#   ./cleanup.sh --force   # Non-interactive – skip all prompts
#   ./cleanup.sh -y        # Same as --force
# ---------------------------------------------------------------------------

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '[cleanup] %s\n' "$1"; }
warn() { printf '[cleanup] WARNING: %s\n' "$1" >&2; }

prompt_yes_no() {
  local label="$1"
  local answer
  printf '  %s [y/N]: ' "$label"
  read -r answer
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes|1|true) return 0 ;;
    *)             return 1 ;;
  esac
}

# Secure-delete a file: overwrite 3 passes then remove
secure_delete_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  local size
  size="$(stat -f%z "$path" 2>/dev/null || stat -c%s "$path" 2>/dev/null || echo 0)"
  if [[ "$size" -eq 0 ]]; then
    rm -f "$path"
    return 0
  fi
  local pass pattern
  for pass in 1 2 3; do
    case "$pass" in
      1) pattern=$'\x00' ;;
      2) pattern=$'\xff' ;;
      3) pattern=$'\xaa' ;;
    esac
    dd if=/dev/zero bs=1 count="$size" 2>/dev/null | tr '\0' "$pattern" | dd of="$path" conv=notrunc bs=1 count="$size" 2>/dev/null
    sync
  done
  # Truncate to zero then delete
  : > "$path"
  sync
  rm -f "$path"
}

# Secure-delete a directory tree
secure_delete_dir() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    return 0
  fi
  # Walk bottom-up, securely delete regular files first
  find "$dir" -type f -print0 2>/dev/null | while IFS= read -r -d '' fpath; do
    secure_delete_file "$fpath"
  done
  # Remove remaining symlinks and empty directories
  find "$dir" -depth -print0 2>/dev/null | while IFS= read -r -d '' entry; do
    if [[ -d "$entry" && "$entry" != "$dir" ]]; then
      rmdir "$entry" 2>/dev/null || true
    elif [[ -L "$entry" || -f "$entry" ]]; then
      rm -f "$entry" 2>/dev/null || true
    fi
  done
  rmdir "$dir" 2>/dev/null || rm -rf "$dir" 2>/dev/null || true
}

FORCE=false
if [[ "${1:-}" == "--force" || "${1:-}" == "-y" ]]; then
  FORCE=true
fi

# ---------------------------------------------------------------------------
# 1. Artifacts directory
# ---------------------------------------------------------------------------

ARTIFACTS_DIR="${ROOT_DIR}/artifacts"
if [[ -d "$ARTIFACTS_DIR" ]]; then
  if $FORCE || prompt_yes_no "Remove artifacts directory (${ARTIFACTS_DIR})?"; then
    log "Securely deleting artifacts directory"
    secure_delete_dir "$ARTIFACTS_DIR"
    log "artifacts/ removed"
  else
    log "Skipped artifacts cleanup"
  fi
else
  log "No artifacts directory found"
fi

# ---------------------------------------------------------------------------
# 2. Desktop-exported reports
# ---------------------------------------------------------------------------

DESKTOP_BASE="${HOME}/Desktop"
for dir_name in "SecurityAuditReports" "Hyntel Report"; do
  DESK_DIR="${DESKTOP_BASE}/${dir_name}"
  if [[ -d "$DESK_DIR" ]]; then
    if $FORCE || prompt_yes_no "Remove Desktop reports (${DESK_DIR})?"; then
      log "Securely deleting ${DESK_DIR}"
      secure_delete_dir "$DESK_DIR"
      log "${dir_name}/ removed"
    else
      log "Skipped ${dir_name} cleanup"
    fi
  else
    log "No ${dir_name} directory on Desktop"
  fi
done

# ---------------------------------------------------------------------------
# 3. __pycache__ and .pyc / .pyo files
# ---------------------------------------------------------------------------

PYCACHE_COUNT=0
if $FORCE || prompt_yes_no "Remove __pycache__ directories and bytecode files?"; then
  log "Scanning for __pycache__ directories and .pyc/.pyo files"
  while IFS= read -r -d '' pycache_dir; do
    # Skip .venv
    if [[ "$pycache_dir" == *"/.venv/"* ]]; then
      continue
    fi
    secure_delete_dir "$pycache_dir"
    PYCACHE_COUNT=$((PYCACHE_COUNT + 1))
  done < <(find "$ROOT_DIR" -type d -name "__pycache__" -print0 2>/dev/null)

  while IFS= read -r -d '' pyc_file; do
    if [[ "$pyc_file" == *"/.venv/"* ]]; then
      continue
    fi
    secure_delete_file "$pyc_file"
    PYCACHE_COUNT=$((PYCACHE_COUNT + 1))
  done < <(find "$ROOT_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -print0 2>/dev/null)

  log "Removed ${PYCACHE_COUNT} cache item(s)"
else
  log "Skipped pycache cleanup"
fi

# ---------------------------------------------------------------------------
# 4. .egg-info directories
# ---------------------------------------------------------------------------

EGG_INFO_COUNT=0
if $FORCE || prompt_yes_no "Remove .egg-info build directories?"; then
  for egg_dir in "$ROOT_DIR"/*.egg-info; do
    if [[ -d "$egg_dir" ]]; then
      log "Removing ${egg_dir}"
      rm -rf "$egg_dir"
      EGG_INFO_COUNT=$((EGG_INFO_COUNT + 1))
    fi
  done
  log "Removed ${EGG_INFO_COUNT} .egg-info directory/directories"
else
  log "Skipped .egg-info cleanup"
fi

# ---------------------------------------------------------------------------
# 5. VERIFICATION_SUMMARY.md
# ---------------------------------------------------------------------------

VERFILE="${ROOT_DIR}/VERIFICATION_SUMMARY.md"
if [[ -f "$VERFILE" ]]; then
  if $FORCE || prompt_yes_no "Remove VERIFICATION_SUMMARY.md?"; then
    log "Securely deleting VERIFICATION_SUMMARY.md"
    secure_delete_file "$VERFILE"
    log "VERIFICATION_SUMMARY.md removed"
  else
    log "Skipped VERIFICATION_SUMMARY.md cleanup"
  fi
else
  log "No VERIFICATION_SUMMARY.md found"
fi

# ---------------------------------------------------------------------------
# 6. .venv directory
# ---------------------------------------------------------------------------

VENV_DIR="${ROOT_DIR}/.venv"
if [[ -d "$VENV_DIR" ]]; then
  if $FORCE || prompt_yes_no "Remove virtual environment (.venv/)? You will need to re-run setup.sh."; then
    log "Removing .venv directory (standard delete — no sensitive data inside venv)"
    rm -rf "$VENV_DIR"
    log ".venv/ removed"
  else
    log "Skipped .venv cleanup"
  fi
else
  log "No .venv directory found"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

log "Cleanup complete"
