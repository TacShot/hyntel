from __future__ import annotations

import json
import platform
import re
import time

from .models import (
    ApplicationFinding,
    CommandResult,
    InstalledApplication,
    ProcessFinding,
    RunningProcess,
)
from .nvd import fetch_cves_by_cpe, search_cpes
from .system_checks import CommandRunner


def _first_version_token(value: str) -> str | None:
    match = re.search(r"\d+(?:\.\d+)+(?:[-+._~a-zA-Z0-9]*)?", value)
    if match:
        return match.group(0)
    return None


def _inventory_linux(runner: CommandRunner, limit: int) -> list[InstalledApplication]:
    if runner.exists("dpkg-query"):
        result = runner.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
        if result.returncode == 0:
            apps = []
            for line in result.stdout.splitlines():
                if not line.strip() or "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                apps.append(InstalledApplication(name=name.strip(), version=version.strip(), source="dpkg"))
            return apps[:limit]

    if runner.exists("rpm"):
        result = runner.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        if result.returncode == 0:
            apps = []
            for line in result.stdout.splitlines():
                if not line.strip() or "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                apps.append(InstalledApplication(name=name.strip(), version=version.strip(), source="rpm"))
            return apps[:limit]

    if runner.exists("pacman"):
        result = runner.run(["pacman", "-Q"])
        if result.returncode == 0:
            apps = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    continue
                apps.append(InstalledApplication(name=parts[0].strip(), version=parts[1].strip(), source="pacman"))
            return apps[:limit]
    return []


def _inventory_macos(runner: CommandRunner, limit: int) -> list[InstalledApplication]:
    if runner.exists("brew"):
        result = runner.run(["brew", "list", "--versions"])
        if result.returncode == 0:
            apps = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                apps.append(InstalledApplication(name=parts[0].strip(), version=parts[1].strip(), source="brew"))
            return apps[:limit]

    result = runner.run(
        [
            "sh",
            "-c",
            "find /Applications -maxdepth 1 -name '*.app' -exec basename {} .app \\; | sort | head -n "
            + str(limit),
        ]
    )
    if result.returncode == 0:
        apps = []
        for line in result.stdout.splitlines():
            if line.strip():
                apps.append(InstalledApplication(name=line.strip(), version="unknown", source="applications"))
        return apps
    return []


def _inventory_windows(runner: CommandRunner, limit: int) -> list[InstalledApplication]:
    script = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -and $_.DisplayVersion } | "
        "Sort-Object DisplayName -Unique | "
        f"Select-Object -First {limit} DisplayName, DisplayVersion | ConvertTo-Json -Compress"
    )
    result = runner.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    if isinstance(payload, dict):
        payload = [payload]

    apps = []
    for item in payload:
        name = str(item.get("DisplayName", "")).strip()
        version = str(item.get("DisplayVersion", "")).strip()
        if name and version:
            apps.append(InstalledApplication(name=name, version=version, source="registry"))
    return apps


def inventory_applications(target_os: str, runner: CommandRunner | None = None, limit: int = 25) -> list[InstalledApplication]:
    active_runner = runner or CommandRunner()
    capped_limit = max(1, limit)
    if target_os == "linux":
        return _inventory_linux(active_runner, capped_limit)
    if target_os == "macos":
        return _inventory_macos(active_runner, capped_limit)
    if target_os == "windows":
        return _inventory_windows(active_runner, capped_limit)
    return []


def map_applications_to_cves(
    applications: list[InstalledApplication],
    cpe_limit: int = 3,
    cve_limit: int = 5,
) -> list[ApplicationFinding]:
    findings: list[ApplicationFinding] = []
    for app in applications:
        version_token = _first_version_token(app.version)
        if not version_token:
            continue

        try:
            cpes = search_cpes(app.name, limit=cpe_limit, timeout=8)
        except Exception:
            continue
        if not cpes:
            continue

        selected_cpe = None
        for cpe in cpes:
            cpe_name = cpe.get("cpeName")
            if cpe_name and f":{version_token}:" in cpe_name:
                selected_cpe = cpe_name
                break
        if selected_cpe is None:
            for cpe in cpes:
                cpe_name = cpe.get("cpeName")
                if cpe_name and ":*:" in cpe_name:
                    selected_cpe = cpe_name.replace(":*:", f":{version_token}:", 1)
                    break

        if not selected_cpe:
            continue

        try:
            cves = fetch_cves_by_cpe(selected_cpe, limit=cve_limit, timeout=8)
        except Exception:
            continue
        if cves:
            findings.append(ApplicationFinding(application=app, cpe_name=selected_cpe, cves=cves))

        time.sleep(0.3)  # Respect NVD rate limit (5 req/sec without API key)
    return findings


def _inventory_unix_processes(runner: CommandRunner, limit: int) -> list[RunningProcess]:
    result = runner.run(["ps", "-axo", "pid=,comm=,args="])
    if result.returncode != 0:
        return []

    processes: list[RunningProcess] = []
    for line in result.stdout.splitlines():
        raw = line.strip()
        if not raw:
            continue
        parts = raw.split(None, 2)
        if len(parts) < 2:
            continue
        pid_text, name = parts[0], parts[1]
        command_line = parts[2] if len(parts) > 2 else name
        if not pid_text.isdigit():
            continue
        processes.append(
            RunningProcess(
                pid=int(pid_text),
                name=name.strip(),
                executable=name.strip(),
                command_line=command_line.strip(),
                source="ps",
            )
        )
        if len(processes) >= limit:
            break
    return processes


def _inventory_windows_processes(runner: CommandRunner, limit: int) -> list[RunningProcess]:
    script = (
        "Get-CimInstance Win32_Process | "
        f"Select-Object -First {limit} ProcessId, Name, ExecutablePath, CommandLine | "
        "ConvertTo-Json -Compress"
    )
    result = runner.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = [payload]

    processes: list[RunningProcess] = []
    for item in payload:
        pid = int(item.get("ProcessId") or 0)
        name = str(item.get("Name") or "").strip()
        if not pid or not name:
            continue
        processes.append(
            RunningProcess(
                pid=pid,
                name=name,
                executable=str(item.get("ExecutablePath") or "").strip() or None,
                command_line=str(item.get("CommandLine") or "").strip() or None,
                source="win32_process",
            )
        )
    return processes


def inventory_running_processes(
    target_os: str,
    runner: CommandRunner | None = None,
    limit: int = 100,
) -> list[RunningProcess]:
    active_runner = runner or CommandRunner()
    capped_limit = max(1, limit)
    if target_os in {"linux", "macos"}:
        return _inventory_unix_processes(active_runner, capped_limit)
    if target_os == "windows":
        return _inventory_windows_processes(active_runner, capped_limit)
    return []


def assess_processes(processes: list[RunningProcess]) -> list[ProcessFinding]:
    findings: list[ProcessFinding] = []
    temp_markers = (
        "/tmp/",
        "/private/var/",
        "/var/tmp/",
        "\\temp\\",
        "\\appdata\\local\\temp\\",
    )
    risky_names = {"powershell", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
    for process in processes:
        reasons: list[str] = []
        command = (process.command_line or "").lower()
        executable = (process.executable or "").lower()
        name = process.name.lower()

        if any(marker in executable for marker in temp_markers) or any(marker in command for marker in temp_markers):
            reasons.append("process is executing from a temporary or user-writable path")
        if name in risky_names and ("-enc " in command or " encodedcommand " in command or "frombase64string" in command):
            reasons.append("process command line looks encoded or obfuscated")
        if re.fullmatch(r"[a-f0-9]{8,}\.?(exe)?", name):
            reasons.append("process name looks randomly generated")

        if reasons:
            action = "Review the process path and parent application, then terminate or quarantine it if untrusted."
            findings.append(
                ProcessFinding(
                    process=process,
                    severity="high" if any("encoded" in reason for reason in reasons) else "medium",
                    reasons=reasons,
                    recommended_action=action,
                )
            )
    return findings
