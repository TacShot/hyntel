"""Cleanup utilities for removing sensitive audit artifacts and residual data.

Provides secure file deletion (overwrite-before-delete) and functions to clean
up generated artifacts, desktop-exported reports, and in-memory scan state so
that details of previously audited machines are not left behind.
"""

from __future__ import annotations

import os
import platform
import shutil
import struct
from pathlib import Path


# ---------------------------------------------------------------------------
# Secure file deletion
# ---------------------------------------------------------------------------

_OVERWRITE_PASSES = 3
_OVERWRITE_PATTERNS = [b"\x00", b"\xff", b"\xaa"]


def secure_delete_file(path: Path) -> bool:
    """Overwrite *path* with random-ish data then delete it.

    Returns True on success, False if the file could not be processed
    (e.g. it does not exist or permission is denied).
    """
    if not path.exists():
        return False
    try:
        size = path.stat().st_size
        with path.open("r+b") as fh:
            for pass_idx in range(_OVERWRITE_PASSES):
                pattern = _OVERWRITE_PATTERNS[pass_idx % len(_OVERWRITE_PATTERNS)]
                fh.seek(0)
                fh.write(pattern * size)
                fh.flush()
                os.fsync(fh.fileno())
            fh.truncate(0)
            fh.flush()
            os.fsync(fh.fileno())
        path.unlink()
        return True
    except (OSError, PermissionError):
        return False


def secure_delete_directory(directory: Path) -> bool:
    """Securely delete every file inside *directory* then remove the directory.

    Symbolic links are removed without following.  Returns True if the
    directory was successfully removed (or did not exist), False otherwise.
    """
    if not directory.exists():
        return True
    try:
        for root, dirs, files in os.walk(directory, topdown=False):
            for fname in files:
                secure_delete_file(Path(root) / fname)
            # Remove empty subdirectories bottom-up
            for dname in dirs:
                subdir = Path(root) / dname
                try:
                    if subdir.is_symlink():
                        subdir.unlink()
                    else:
                        subdir.rmdir()
                except OSError:
                    pass
        # Remove the now-empty root directory
        if directory.is_symlink():
            directory.unlink()
        else:
            directory.rmdir()
        return True
    except (OSError, PermissionError):
        return False


# ---------------------------------------------------------------------------
# Project-specific cleanup helpers
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Return the directory that contains the pyproject.toml (project root)."""
    # cleanup.py lives inside security_audit_tool/, so go one level up.
    return Path(__file__).resolve().parent.parent


def default_artifacts_dir() -> Path:
    """Return the default artifacts directory (``<project_root>/artifacts``)."""
    return _project_root() / "artifacts"


def desktop_audit_reports_dir() -> Path:
    """Return the platform-specific Desktop audit export directory."""
    if os.name == "nt":
        base = os.environ.get("USERPROFILE")
        if base:
            return Path(base) / "Desktop" / "SecurityAuditReports"
    return Path.home() / "Desktop" / "SecurityAuditReports"


def desktop_hyntel_report_dir() -> Path:
    """Return the platform-specific Desktop Hyntel Report directory."""
    if os.name == "nt":
        base = os.environ.get("USERPROFILE")
        if base:
            return Path(base) / "Desktop" / "Hyntel Report"
    return Path.home() / "Desktop" / "Hyntel Report"


def cleanup_artifacts(artifacts_dir: Path | None = None) -> dict[str, bool]:
    """Securely remove all files under the artifacts directory.

    Parameters
    ----------
    artifacts_dir:
        Directory to clean.  Defaults to ``<project_root>/artifacts``.

    Returns
    -------
    dict
        ``{"artifacts": bool}`` where *True* means the directory was removed.
    """
    target = artifacts_dir or default_artifacts_dir()
    return {"artifacts": secure_delete_directory(target)}


def cleanup_desktop_reports() -> dict[str, bool]:
    """Securely remove Desktop-exported report directories.

    Cleans both ``SecurityAuditReports`` and ``Hyntel Report`` on the
    current user's Desktop.
    """
    results: dict[str, bool] = {}
    for label, path_func in [
        ("security_audit_reports", desktop_audit_reports_dir),
        ("hyntel_report", desktop_hyntel_report_dir),
    ]:
        d = path_func()
        results[label] = secure_delete_directory(d)
    return results


def cleanup_pycache(project_root: Path | None = None) -> dict[str, bool]:
    """Remove ``__pycache__`` directories and ``.pyc`` / ``.pyo`` files.

    Parameters
    ----------
    project_root:
        The project root to scan.  Defaults to the directory containing
        ``pyproject.toml``.
    """
    root = project_root or _project_root()
    success = True
    count = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        dp = Path(dirpath)
        # Skip .venv hierarchy
        if ".venv" in dp.parts:
            continue
        # Remove __pycache__ dirs
        pycache = dp / "__pycache__"
        if pycache.is_dir():
            if not secure_delete_directory(pycache):
                success = False
            else:
                count += 1
        # Remove stray .pyc / .pyo files
        for fname in filenames:
            if fname.endswith((".pyc", ".pyo")):
                fpath = dp / fname
                if not secure_delete_file(fpath):
                    success = False
                else:
                    count += 1
    return {"pycache": success, "items_removed": count > 0}


def cleanup_egg_info(project_root: Path | None = None) -> dict[str, bool]:
    """Remove ``*.egg-info`` directories under the project root."""
    root = project_root or _project_root()
    success = True
    for item in root.iterdir():
        if item.is_dir() and item.name.endswith(".egg-info"):
            if not secure_delete_directory(item):
                success = False
    return {"egg_info": success}


def cleanup_verification_summary(project_root: Path | None = None) -> dict[str, bool]:
    """Remove ``VERIFICATION_SUMMARY.md`` if it exists."""
    root = project_root or _project_root()
    vsum = root / "VERIFICATION_SUMMARY.md"
    if vsum.exists():
        return {"verification_summary": secure_delete_file(vsum)}
    return {"verification_summary": True}


def cleanup_venv(project_root: Path | None = None) -> dict[str, bool]:
    """Remove the ``.venv`` directory.

    Because .venv may contain thousands of files, secure overwrite is not
    practical — we delete normally (``shutil.rmtree``) for performance.
    Sensitive user data is not stored inside .venv.
    """
    root = project_root or _project_root()
    venv = root / ".venv"
    if not venv.exists():
        return {"venv": True}
    try:
        shutil.rmtree(venv)
        return {"venv": True}
    except (OSError, PermissionError):
        return {"venv": False}


def cleanup_all(
    *,
    include_venv: bool = False,
    include_desktop: bool = True,
    include_pycache: bool = True,
    include_egg_info: bool = True,
    include_verification: bool = True,
    artifacts_dir: Path | None = None,
    project_root: Path | None = None,
) -> dict[str, dict[str, bool]]:
    """Run all cleanup operations and return a summary of results.

    Parameters
    ----------
    include_venv:
        Also remove the ``.venv`` directory (off by default because the user
        would need to re-run ``setup.sh`` afterwards).
    include_desktop:
        Remove Desktop-exported report directories.
    include_pycache:
        Remove ``__pycache__`` and bytecode files.
    include_egg_info:
        Remove ``*.egg-info`` directories.
    include_verification:
        Remove ``VERIFICATION_SUMMARY.md``.
    artifacts_dir:
        Override the default artifacts directory.
    project_root:
        Override the detected project root.
    """
    results: dict[str, dict[str, bool]] = {}
    results["artifacts"] = cleanup_artifacts(artifacts_dir)
    if include_desktop:
        results["desktop_reports"] = cleanup_desktop_reports()
    if include_pycache:
        results["pycache"] = cleanup_pycache(project_root)
    if include_egg_info:
        results["egg_info"] = cleanup_egg_info(project_root)
    if include_verification:
        results["verification_summary"] = cleanup_verification_summary(project_root)
    if include_venv:
        results["venv"] = cleanup_venv(project_root)
    return results


def cleanup_memory_state(gui_instance: object | None = None) -> dict[str, bool]:
    """Clear in-memory scan results so they cannot leak between audits.

    If *gui_instance* is a ``SecurityAuditGUI``, its ``current_*`` attributes
    are reset to empty/None values.
    """
    results: dict[str, bool] = {"memory_state": True}
    if gui_instance is not None:
        try:
            gui_instance.current_results = []  # type: ignore[attr-defined]
            gui_instance.current_target_os = None  # type: ignore[attr-defined]
            gui_instance.current_remediation_path = None  # type: ignore[attr-defined]
            gui_instance.current_application_findings = None  # type: ignore[attr-defined]
            gui_instance.current_applications = []  # type: ignore[attr-defined]
            gui_instance.current_drivers = []  # type: ignore[attr-defined]
            gui_instance.current_processes = []  # type: ignore[attr-defined]
            gui_instance.current_process_findings = []  # type: ignore[attr-defined]
            gui_instance.current_os_info = None  # type: ignore[attr-defined]
            gui_instance.current_export_paths = {}  # type: ignore[attr-defined]
        except Exception:
            results["memory_state"] = False
    return results
