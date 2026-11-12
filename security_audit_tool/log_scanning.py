"""Bounded, read-only collection of security-relevant host log events."""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LogEvent:
    timestamp: str
    source: str
    event_id: str | None
    level: str
    message: str


@dataclass
class LogScanResult:
    platform: str
    scanned: bool
    source: str
    events: list[LogEvent]
    warnings: list[str]


def _run(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False,
                          shell=False, timeout=timeout)


def scan_security_logs(target_os: str | None = None, limit: int = 200,
                       since_hours: int = 24) -> LogScanResult:
    """Collect recent security-relevant events. No logs are modified or uploaded."""
    target = target_os or {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), platform.system().lower())
    cap = max(1, min(int(limit), 2000))
    hours = max(1, min(int(since_hours), 720))
    events: list[LogEvent] = []
    warnings: list[str] = []
    source = ""
    try:
        if target == "windows":
            source = "Windows Security event log"
            ps = (
                "$ids=@(4624,4625,4634,4648,4672,4688,4697,4720,4728,4732,4740,1102);"
                f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=$ids;StartTime=(Get-Date).AddHours(-{hours})}} "
                f"-MaxEvents {cap} -ErrorAction Stop | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Depth 3 -Compress"
            )
            result = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
            if result.returncode:
                warnings.append((result.stderr or result.stdout or "Unable to read Security event log.").strip()[:1000])
            elif result.stdout.strip():
                payload = json.loads(result.stdout)
                for item in payload if isinstance(payload, list) else [payload]:
                    events.append(LogEvent(str(item.get("TimeCreated") or ""), str(item.get("ProviderName") or source),
                                           str(item.get("Id") or ""), str(item.get("LevelDisplayName") or "Information"),
                                           str(item.get("Message") or "")[:4000]))
        elif target == "macos":
            source = "macOS unified log"
            predicate = '(eventMessage CONTAINS[c] "authentication" OR eventMessage CONTAINS[c] "sudo" OR eventMessage CONTAINS[c] "failed login" OR process == "sshd")'
            result = _run(["log", "show", "--style", "json", "--last", f"{hours}h", "--predicate", predicate], timeout=45)
            if result.returncode:
                warnings.append((result.stderr or "Unable to read unified log.").strip()[:1000])
            elif result.stdout.strip():
                payload = json.loads(result.stdout)
                for item in payload[-cap:] if isinstance(payload, list) else []:
                    events.append(LogEvent(str(item.get("timestamp") or ""), str(item.get("process") or source),
                                           None, str(item.get("messageType") or "Default"),
                                           str(item.get("eventMessage") or "")[:4000]))
        elif target == "linux":
            source = "systemd journal/authentication logs"
            if shutil.which("journalctl"):
                result = _run(["journalctl", "--since", f"{hours} hours ago", "--no-pager", "-o", "json",
                               "-n", str(cap), "SYSLOG_FACILITY=4"], timeout=30)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        events.append(LogEvent(str(item.get("__REALTIME_TIMESTAMP") or ""),
                                               str(item.get("SYSLOG_IDENTIFIER") or source),
                                               str(item.get("SYSLOG_PID") or "") or None,
                                               str(item.get("PRIORITY") or "unknown"),
                                               str(item.get("MESSAGE") or "")[:4000]))
                else:
                    warnings.append((result.stderr or "journalctl query failed").strip()[:1000])
            else:
                candidates = [Path("/var/log/auth.log"), Path("/var/log/secure")]
                found = False
                for path in candidates:
                    if path.is_file():
                        found = True
                        try:
                            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-cap:]
                            events.extend(LogEvent("", str(path), None, "unclassified", line[:4000]) for line in lines)
                        except OSError as exc:
                            warnings.append(f"{path}: {exc}")
                if not found:
                    warnings.append("Neither journalctl nor readable auth.log/secure was available.")
        else:
            warnings.append(f"Unsupported target OS: {target}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        warnings.append(f"Log collection failed: {exc}")
    return LogScanResult(target, bool(events) or not warnings, source, events[:cap], warnings)


def result_to_dict(result: LogScanResult) -> dict[str, Any]:
    return {"platform": result.platform, "scanned": result.scanned, "source": result.source,
            "event_count": len(result.events), "events": [asdict(event) for event in result.events],
            "warnings": result.warnings}
