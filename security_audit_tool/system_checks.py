from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import replace

from .models import AuditRule, CVEQuery, CheckResult, CommandResult


class CommandRunner:
    def run(self, command: list[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(returncode=127, stdout="", stderr="command not found")
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )

    def exists(self, executable: str) -> bool:
        return shutil.which(executable) is not None


def detect_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return "unknown"


def _pass_result(rule_id: str, details: str, observed: str | None = None) -> CheckResult:
    return CheckResult(rule_id=rule_id, status="pass", details=details, observed_value=observed)


def _fail_result(rule_id: str, details: str, observed: str | None = None) -> CheckResult:
    return CheckResult(rule_id=rule_id, status="fail", details=details, observed_value=observed)


def _skip_result(rule_id: str, details: str) -> CheckResult:
    return CheckResult(rule_id=rule_id, status="skip", details=details)


def _linux_firewall(runner: CommandRunner) -> CheckResult:
    if runner.exists("ufw"):
        result = runner.run(["ufw", "status"])
        output = (result.stdout or result.stderr).lower()
        if "status: active" in output:
            return _pass_result("linux_firewall_enabled", "UFW is active.", result.stdout)
        return _fail_result("linux_firewall_enabled", "UFW is installed but inactive.", result.stdout or result.stderr)

    if runner.exists("systemctl"):
        for service in ("firewalld", "nftables"):
            result = runner.run(["systemctl", "is-active", service])
            if result.returncode == 0 and result.stdout.strip() == "active":
                return _pass_result("linux_firewall_enabled", f"{service} is active.", service)
        return _fail_result(
            "linux_firewall_enabled",
            "No supported active firewall service detected.",
            "firewalld/nftables inactive",
        )

    return _skip_result("linux_firewall_enabled", "No supported firewall tool found on host.")


def _read_sshd_config_value(runner: CommandRunner, key: str) -> str | None:
    config_path = "/etc/ssh/sshd_config"
    result = runner.run(["sh", "-c", f"test -f {config_path} && sed -n 's/^\\s*{key}\\s\\+//Ip' {config_path} | tail -n 1"])
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout.strip()


def _linux_sshd_root_login(runner: CommandRunner) -> CheckResult:
    value = _read_sshd_config_value(runner, "PermitRootLogin")
    if value is None:
        return _skip_result("linux_sshd_root_login_disabled", "Could not determine PermitRootLogin from sshd_config.")
    if value.lower() in {"no", "prohibit-password"}:
        return _pass_result("linux_sshd_root_login_disabled", "Root SSH login is disabled.", value)
    return _fail_result("linux_sshd_root_login_disabled", "Root SSH login is allowed.", value)


def _linux_sshd_password_auth(runner: CommandRunner) -> CheckResult:
    value = _read_sshd_config_value(runner, "PasswordAuthentication")
    if value is None:
        return _skip_result("linux_sshd_password_auth_disabled", "Could not determine PasswordAuthentication from sshd_config.")
    if value.lower() == "no":
        return _pass_result("linux_sshd_password_auth_disabled", "SSH password authentication is disabled.", value)
    return _fail_result("linux_sshd_password_auth_disabled", "SSH password authentication is enabled.", value)


def _linux_auto_updates(runner: CommandRunner) -> CheckResult:
    if runner.exists("systemctl"):
        for service in ("apt-daily-upgrade.timer", "dnf-automatic.timer", "unattended-upgrades.service"):
            result = runner.run(["systemctl", "is-enabled", service])
            if result.returncode == 0 and result.stdout.strip() in {"enabled", "static"}:
                return _pass_result("linux_auto_updates_enabled", f"{service} is enabled.", result.stdout)
    return _fail_result("linux_auto_updates_enabled", "No supported automatic update service is enabled.")


def _macos_firewall(runner: CommandRunner) -> CheckResult:
    result = runner.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    output = f"{result.stdout} {result.stderr}".lower()
    if "enabled" in output:
        return _pass_result("macos_firewall_enabled", "macOS application firewall is enabled.", result.stdout)
    if result.returncode == 127:
        return _skip_result("macos_firewall_enabled", "socketfilterfw is not available.")
    return _fail_result("macos_firewall_enabled", "macOS application firewall is disabled.", result.stdout or result.stderr)


def _macos_filevault(runner: CommandRunner) -> CheckResult:
    result = runner.run(["fdesetup", "status"])
    output = f"{result.stdout} {result.stderr}".lower()
    if "filevault is on" in output:
        return _pass_result("macos_filevault_enabled", "FileVault is enabled.", result.stdout)
    if result.returncode == 127:
        return _skip_result("macos_filevault_enabled", "fdesetup is not available.")
    if "unknown volume or device specifier" in output or "not supported" in output:
        return _skip_result("macos_filevault_enabled", "FileVault status is unavailable in the current execution environment.")
    return _fail_result("macos_filevault_enabled", "FileVault is not enabled.", result.stdout or result.stderr)


def _macos_remote_login(runner: CommandRunner) -> CheckResult:
    result = runner.run(["systemsetup", "-getremotelogin"])
    output = f"{result.stdout} {result.stderr}".lower()
    if "off" in output:
        return _pass_result("macos_remote_login_disabled", "Remote Login is disabled.", result.stdout)
    if "requires admin privileges" in output or "administrator access" in output:
        return _skip_result("macos_remote_login_disabled", "Remote Login status requires elevated privileges to read.")
    return _fail_result("macos_remote_login_disabled", "Remote Login is enabled.", result.stdout or result.stderr)


def _macos_auto_updates(runner: CommandRunner) -> CheckResult:
    result = runner.run(["softwareupdate", "--schedule"])
    output = f"{result.stdout} {result.stderr}".lower()
    if "on" in output:
        return _pass_result("macos_auto_updates_enabled", "Automatic updates are enabled.", result.stdout)
    return _fail_result("macos_auto_updates_enabled", "Automatic updates are disabled.", result.stdout or result.stderr)


def _powershell(runner: CommandRunner, script: str) -> CommandResult:
    return runner.run(
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


def _windows_firewall(runner: CommandRunner) -> CheckResult:
    result = _powershell(
        runner,
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",
    )
    output = result.stdout.strip()
    if result.returncode == 127:
        return _skip_result("windows_firewall_enabled", "powershell.exe is not available.")
    enabled_count = output.lower().count('"enabled":true')
    if enabled_count >= 3:
        return _pass_result("windows_firewall_enabled", "All Windows Firewall profiles are enabled.", output)
    return _fail_result("windows_firewall_enabled", "One or more Windows Firewall profiles are disabled.", output or result.stderr)


def _windows_bitlocker(runner: CommandRunner) -> CheckResult:
    result = _powershell(
        runner,
        "Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus | ConvertTo-Json -Compress",
    )
    output = result.stdout.strip()
    if result.returncode == 127:
        return _skip_result("windows_bitlocker_enabled", "powershell.exe is not available.")
    if "On" in output or '"ProtectionStatus":1' in output:
        return _pass_result("windows_bitlocker_enabled", "BitLocker protection is enabled on at least one volume.", output)
    return _fail_result("windows_bitlocker_enabled", "BitLocker protection is not enabled.", output or result.stderr)


def _windows_rdp(runner: CommandRunner) -> CheckResult:
    result = _powershell(
        runner,
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
    )
    output = result.stdout.strip()
    if result.returncode == 127:
        return _skip_result("windows_rdp_disabled", "powershell.exe is not available.")
    if output == "1":
        return _pass_result("windows_rdp_disabled", "Remote Desktop is disabled.", output)
    return _fail_result("windows_rdp_disabled", "Remote Desktop is enabled.", output or result.stderr)


def _windows_defender_realtime(runner: CommandRunner) -> CheckResult:
    result = _powershell(
        runner,
        "(Get-MpPreference).DisableRealtimeMonitoring",
    )
    output = result.stdout.strip()
    if result.returncode == 127:
        return _skip_result("windows_defender_realtime_enabled", "powershell.exe is not available.")
    if output == "False":
        return _pass_result("windows_defender_realtime_enabled", "Microsoft Defender real-time monitoring is enabled.", output)
    return _fail_result("windows_defender_realtime_enabled", "Microsoft Defender real-time monitoring is disabled.", output or result.stderr)


RULES: list[AuditRule] = [
    AuditRule(
        identifier="linux_firewall_enabled",
        platform="linux",
        title="Linux firewall enabled",
        description="Verify that a host firewall is active.",
        rationale="An active host firewall reduces unnecessary service exposure.",
        severity="high",
        check=_linux_firewall,
        remediation=[
            "sudo ufw enable",
            "sudo systemctl enable --now firewalld",
        ],
        cve_queries=[CVEQuery(keyword="linux firewall exposed service remote code execution")],
    ),
    AuditRule(
        identifier="linux_sshd_root_login_disabled",
        platform="linux",
        title="Linux SSH root login disabled",
        description="Ensure OpenSSH root login is disabled.",
        rationale="Root SSH access increases brute-force and privilege abuse risk.",
        severity="critical",
        check=_linux_sshd_root_login,
        remediation=[
            "sudo sed -i.bak 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
        cve_queries=[CVEQuery(keyword="OpenSSH privilege escalation authentication bypass root login")],
    ),
    AuditRule(
        identifier="linux_sshd_password_auth_disabled",
        platform="linux",
        title="Linux SSH password authentication disabled",
        description="Ensure SSH password authentication is disabled in favor of keys.",
        rationale="Password-based SSH is more exposed to credential attacks.",
        severity="high",
        check=_linux_sshd_password_auth,
        remediation=[
            "sudo sed -i.bak 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
        cve_queries=[CVEQuery(keyword="OpenSSH password authentication brute force vulnerability")],
    ),
    AuditRule(
        identifier="linux_auto_updates_enabled",
        platform="linux",
        title="Linux automatic updates enabled",
        description="Verify that security updates can be applied automatically.",
        rationale="Patch latency increases exposure to known CVEs.",
        severity="medium",
        check=_linux_auto_updates,
        remediation=[
            "sudo systemctl enable --now apt-daily-upgrade.timer",
            "sudo systemctl enable --now dnf-automatic.timer",
        ],
        cve_queries=[CVEQuery(keyword="linux kernel privilege escalation local vulnerability")],
    ),
    AuditRule(
        identifier="macos_firewall_enabled",
        platform="macos",
        title="macOS firewall enabled",
        description="Verify the built-in macOS firewall is enabled.",
        rationale="The application firewall limits unsolicited inbound access.",
        severity="high",
        check=_macos_firewall,
        remediation=[
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        ],
        cve_queries=[CVEQuery(keyword="macOS remote service vulnerability firewall exposure")],
    ),
    AuditRule(
        identifier="macos_filevault_enabled",
        platform="macos",
        title="macOS FileVault enabled",
        description="Verify FileVault disk encryption is enabled.",
        rationale="Disk encryption protects data at rest after device loss or theft.",
        severity="high",
        check=_macos_filevault,
        remediation=[
            "sudo fdesetup enable",
        ],
        cve_queries=[CVEQuery(keyword="macOS data exposure encryption bypass")],
    ),
    AuditRule(
        identifier="macos_remote_login_disabled",
        platform="macos",
        title="macOS Remote Login disabled",
        description="Verify SSH-based remote login is disabled unless required.",
        rationale="Unused remote access services enlarge the attack surface.",
        severity="high",
        check=_macos_remote_login,
        remediation=[
            "sudo systemsetup -setremotelogin off",
        ],
        cve_queries=[CVEQuery(keyword="OpenSSH macOS remote login vulnerability")],
    ),
    AuditRule(
        identifier="macos_auto_updates_enabled",
        platform="macos",
        title="macOS automatic updates enabled",
        description="Verify automatic updates are enabled.",
        rationale="Security updates reduce exposure to published CVEs.",
        severity="medium",
        check=_macos_auto_updates,
        remediation=[
            "sudo softwareupdate --schedule on",
        ],
        cve_queries=[CVEQuery(keyword="macOS privilege escalation vulnerability security update")],
    ),
    AuditRule(
        identifier="windows_firewall_enabled",
        platform="windows",
        title="Windows Firewall enabled",
        description="Verify all Windows Firewall profiles are enabled.",
        rationale="Firewall profiles reduce inbound attack surface across network types.",
        severity="high",
        check=_windows_firewall,
        remediation=[
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        ],
        cve_queries=[CVEQuery(keyword="Windows remote code execution exposed service firewall")],
    ),
    AuditRule(
        identifier="windows_bitlocker_enabled",
        platform="windows",
        title="Windows BitLocker enabled",
        description="Verify BitLocker protection is enabled.",
        rationale="Disk encryption protects offline data disclosure scenarios.",
        severity="high",
        check=_windows_bitlocker,
        remediation=[
            "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly",
        ],
        cve_queries=[CVEQuery(keyword="Windows data exposure encryption bypass")],
    ),
    AuditRule(
        identifier="windows_rdp_disabled",
        platform="windows",
        title="Windows Remote Desktop disabled",
        description="Verify Remote Desktop is disabled unless explicitly required.",
        rationale="Unneeded remote administration services increase attack surface.",
        severity="critical",
        check=_windows_rdp,
        remediation=[
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1",
        ],
        cve_queries=[CVEQuery(keyword="Windows Remote Desktop remote code execution")],
    ),
    AuditRule(
        identifier="windows_defender_realtime_enabled",
        platform="windows",
        title="Windows Defender real-time monitoring enabled",
        description="Verify Microsoft Defender real-time monitoring is enabled.",
        rationale="Real-time scanning helps prevent known malware execution paths.",
        severity="high",
        check=_windows_defender_realtime,
        remediation=[
            "Set-MpPreference -DisableRealtimeMonitoring $false",
        ],
        cve_queries=[CVEQuery(keyword="Microsoft Defender bypass vulnerability malware")],
    ),
]


def get_rules(target_platform: str) -> list[AuditRule]:
    return [rule for rule in RULES if rule.platform == target_platform]


def run_audit(target_platform: str, runner: CommandRunner | None = None) -> list[tuple[AuditRule, CheckResult]]:
    active_runner = runner or CommandRunner()
    results: list[tuple[AuditRule, CheckResult]] = []
    for rule in get_rules(target_platform):
        raw_result = rule.check(active_runner)
        results.append((rule, replace(raw_result, remediation=rule.remediation)))
    return results
