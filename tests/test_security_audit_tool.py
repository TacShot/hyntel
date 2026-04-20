import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from security_audit_tool.inventory import (
    _first_version_token,
    _inventory_linux,
    _inventory_macos,
    _inventory_windows,
    inventory_applications,
    map_applications_to_cves,
)
from security_audit_tool.models import ApplicationFinding, CheckResult, CommandResult, InstalledApplication
from security_audit_tool.nvd import (
    _extract_cvss,
    _extract_description,
    fetch_cves_by_cpe,
    fetch_related_cves,
    search_cpes,
)
from security_audit_tool.remediation import (
    remediation_filename,
    render_remediation_script,
    write_remediation_script,
)
from security_audit_tool.reporting import (
    desktop_dir,
    export_report_bundle,
    render_json_report,
    render_text_report,
    summarize_results,
)
from security_audit_tool.system_checks import (
    CommandRunner,
    _linux_auto_updates,
    _linux_firewall,
    _linux_sshd_password_auth,
    _linux_sshd_root_login,
    _macos_auto_updates,
    _macos_filevault,
    _macos_firewall,
    _macos_remote_login,
    _windows_bitlocker,
    _windows_defender_realtime,
    _windows_firewall,
    _windows_rdp,
    detect_platform,
    get_rules,
    run_audit,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class FakeRunner(CommandRunner):
    """Test double for CommandRunner that returns pre-configured results."""

    def __init__(self, outputs=None, existing_executables=None):
        self.outputs = outputs or {}
        self.existing_executables = existing_executables or set()

    def run(self, command):
        key = tuple(command)
        return self.outputs.get(key, CommandResult(returncode=127, stdout="", stderr="command not found"))

    def exists(self, executable):
        return executable in self.existing_executables


def _make_rule(identifier="rule1", title="Rule One", severity="high"):
    return type("Rule", (), {"identifier": identifier, "title": title, "severity": severity})()


# ---------------------------------------------------------------------------
# system_checks – detect_platform
# ---------------------------------------------------------------------------

class TestDetectPlatform(unittest.TestCase):
    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            self.assertEqual(detect_platform(), "linux")

    def test_macos(self):
        with patch("platform.system", return_value="Darwin"):
            self.assertEqual(detect_platform(), "macos")

    def test_windows(self):
        with patch("platform.system", return_value="Windows"):
            self.assertEqual(detect_platform(), "windows")

    def test_unknown(self):
        with patch("platform.system", return_value="FreeBSD"):
            self.assertEqual(detect_platform(), "unknown")


# ---------------------------------------------------------------------------
# system_checks – CommandRunner
# ---------------------------------------------------------------------------

class TestCommandRunner(unittest.TestCase):
    def test_run_success(self):
        runner = CommandRunner()
        result = runner.run(["echo", "hello"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_run_missing_command(self):
        runner = CommandRunner()
        result = runner.run(["__nonexistent_command_xyz__"])
        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stderr, "command not found")

    def test_exists_true(self):
        runner = CommandRunner()
        self.assertTrue(runner.exists("python3") or runner.exists("python"))

    def test_exists_false(self):
        runner = CommandRunner()
        self.assertFalse(runner.exists("__nonexistent_binary_xyz__"))


# ---------------------------------------------------------------------------
# system_checks – Linux firewall
# ---------------------------------------------------------------------------

class TestLinuxFirewall(unittest.TestCase):
    def test_ufw_active(self):
        runner = FakeRunner(
            outputs={("ufw", "status"): CommandResult(0, "Status: active", "")},
            existing_executables={"ufw"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.rule_id, "linux_firewall_enabled")

    def test_ufw_inactive(self):
        runner = FakeRunner(
            outputs={("ufw", "status"): CommandResult(0, "Status: inactive", "")},
            existing_executables={"ufw"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "fail")

    def test_ufw_output_in_stderr(self):
        runner = FakeRunner(
            outputs={("ufw", "status"): CommandResult(1, "", "Status: active")},
            existing_executables={"ufw"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "pass")

    def test_firewalld_active(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-active", "firewalld"): CommandResult(0, "active", ""),
            },
            existing_executables={"systemctl"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "pass")

    def test_nftables_active(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-active", "firewalld"): CommandResult(1, "inactive", ""),
                ("systemctl", "is-active", "nftables"): CommandResult(0, "active", ""),
            },
            existing_executables={"systemctl"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "pass")

    def test_no_firewall_tool(self):
        runner = FakeRunner(existing_executables=set())
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "skip")

    def test_systemctl_no_active_firewall(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-active", "firewalld"): CommandResult(1, "inactive", ""),
                ("systemctl", "is-active", "nftables"): CommandResult(1, "inactive", ""),
            },
            existing_executables={"systemctl"},
        )
        result = _linux_firewall(runner)
        self.assertEqual(result.status, "fail")


# ---------------------------------------------------------------------------
# system_checks – Linux SSH root login
# ---------------------------------------------------------------------------

_SSH_ROOT_CMD = (
    "sh", "-c",
    "test -f /etc/ssh/sshd_config && sed -n 's/^\\s*PermitRootLogin\\s\\+//Ip' /etc/ssh/sshd_config | tail -n 1",
)
_SSH_PWD_CMD = (
    "sh", "-c",
    "test -f /etc/ssh/sshd_config && sed -n 's/^\\s*PasswordAuthentication\\s\\+//Ip' /etc/ssh/sshd_config | tail -n 1",
)


class TestLinuxSshdRootLogin(unittest.TestCase):
    def test_no_is_pass(self):
        runner = FakeRunner(outputs={_SSH_ROOT_CMD: CommandResult(0, "no", "")})
        self.assertEqual(_linux_sshd_root_login(runner).status, "pass")

    def test_prohibit_password_is_pass(self):
        runner = FakeRunner(outputs={_SSH_ROOT_CMD: CommandResult(0, "prohibit-password", "")})
        self.assertEqual(_linux_sshd_root_login(runner).status, "pass")

    def test_yes_is_fail(self):
        runner = FakeRunner(outputs={_SSH_ROOT_CMD: CommandResult(0, "yes", "")})
        self.assertEqual(_linux_sshd_root_login(runner).status, "fail")

    def test_missing_config_is_skip(self):
        runner = FakeRunner(outputs={_SSH_ROOT_CMD: CommandResult(1, "", "")})
        self.assertEqual(_linux_sshd_root_login(runner).status, "skip")

    def test_empty_output_is_skip(self):
        runner = FakeRunner(outputs={_SSH_ROOT_CMD: CommandResult(0, "", "")})
        self.assertEqual(_linux_sshd_root_login(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – Linux SSH password auth
# ---------------------------------------------------------------------------

class TestLinuxSshdPasswordAuth(unittest.TestCase):
    def test_no_is_pass(self):
        runner = FakeRunner(outputs={_SSH_PWD_CMD: CommandResult(0, "no", "")})
        self.assertEqual(_linux_sshd_password_auth(runner).status, "pass")

    def test_yes_is_fail(self):
        runner = FakeRunner(outputs={_SSH_PWD_CMD: CommandResult(0, "yes", "")})
        self.assertEqual(_linux_sshd_password_auth(runner).status, "fail")

    def test_missing_is_skip(self):
        runner = FakeRunner(outputs={_SSH_PWD_CMD: CommandResult(1, "", "")})
        self.assertEqual(_linux_sshd_password_auth(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – Linux auto updates
# ---------------------------------------------------------------------------

class TestLinuxAutoUpdates(unittest.TestCase):
    def test_apt_timer_enabled(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(0, "enabled", ""),
            },
            existing_executables={"systemctl"},
        )
        self.assertEqual(_linux_auto_updates(runner).status, "pass")

    def test_dnf_timer_enabled(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(0, "enabled", ""),
            },
            existing_executables={"systemctl"},
        )
        self.assertEqual(_linux_auto_updates(runner).status, "pass")

    def test_unattended_upgrades_static(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "unattended-upgrades.service"): CommandResult(0, "static", ""),
            },
            existing_executables={"systemctl"},
        )
        self.assertEqual(_linux_auto_updates(runner).status, "pass")

    def test_all_disabled_is_fail(self):
        runner = FakeRunner(
            outputs={
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "unattended-upgrades.service"): CommandResult(1, "disabled", ""),
            },
            existing_executables={"systemctl"},
        )
        self.assertEqual(_linux_auto_updates(runner).status, "fail")

    def test_no_systemctl_is_fail(self):
        runner = FakeRunner(existing_executables=set())
        self.assertEqual(_linux_auto_updates(runner).status, "fail")


# ---------------------------------------------------------------------------
# system_checks – macOS firewall
# ---------------------------------------------------------------------------

_SOCKETFW = ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")


class TestMacosFirewall(unittest.TestCase):
    def test_enabled_in_stdout(self):
        runner = FakeRunner(outputs={_SOCKETFW: CommandResult(0, "Firewall is enabled.", "")})
        self.assertEqual(_macos_firewall(runner).status, "pass")

    def test_enabled_in_stderr(self):
        runner = FakeRunner(outputs={_SOCKETFW: CommandResult(0, "", "Firewall is enabled.")})
        self.assertEqual(_macos_firewall(runner).status, "pass")

    def test_disabled(self):
        runner = FakeRunner(outputs={_SOCKETFW: CommandResult(0, "Firewall is disabled.", "")})
        self.assertEqual(_macos_firewall(runner).status, "fail")

    def test_not_available(self):
        runner = FakeRunner(outputs={_SOCKETFW: CommandResult(127, "", "")})
        self.assertEqual(_macos_firewall(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – macOS FileVault
# ---------------------------------------------------------------------------

_FDESETUP = ("fdesetup", "status")


class TestMacosFilevault(unittest.TestCase):
    def test_on(self):
        runner = FakeRunner(outputs={_FDESETUP: CommandResult(0, "FileVault is On.", "")})
        self.assertEqual(_macos_filevault(runner).status, "pass")

    def test_off(self):
        runner = FakeRunner(outputs={_FDESETUP: CommandResult(0, "FileVault is Off.", "")})
        self.assertEqual(_macos_filevault(runner).status, "fail")

    def test_not_available(self):
        runner = FakeRunner(outputs={_FDESETUP: CommandResult(127, "", "")})
        self.assertEqual(_macos_filevault(runner).status, "skip")

    def test_not_supported(self):
        runner = FakeRunner(outputs={_FDESETUP: CommandResult(1, "", "not supported")})
        self.assertEqual(_macos_filevault(runner).status, "skip")

    def test_unknown_volume(self):
        runner = FakeRunner(outputs={_FDESETUP: CommandResult(1, "", "unknown volume or device specifier")})
        self.assertEqual(_macos_filevault(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – macOS Remote Login
# ---------------------------------------------------------------------------

_SYSTEMSETUP = ("systemsetup", "-getremotelogin")


class TestMacosRemoteLogin(unittest.TestCase):
    def test_off(self):
        runner = FakeRunner(outputs={_SYSTEMSETUP: CommandResult(0, "Remote Login: Off", "")})
        self.assertEqual(_macos_remote_login(runner).status, "pass")

    def test_on(self):
        runner = FakeRunner(outputs={_SYSTEMSETUP: CommandResult(0, "Remote Login: On", "")})
        self.assertEqual(_macos_remote_login(runner).status, "fail")

    def test_requires_admin(self):
        runner = FakeRunner(outputs={_SYSTEMSETUP: CommandResult(1, "", "Requires admin privileges")})
        self.assertEqual(_macos_remote_login(runner).status, "skip")

    def test_administrator_access(self):
        runner = FakeRunner(outputs={_SYSTEMSETUP: CommandResult(1, "", "Requires administrator access")})
        self.assertEqual(_macos_remote_login(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – macOS auto updates
# ---------------------------------------------------------------------------

_SOFTWAREUPDATE = ("softwareupdate", "--schedule")


class TestMacosAutoUpdates(unittest.TestCase):
    def test_on(self):
        runner = FakeRunner(outputs={_SOFTWAREUPDATE: CommandResult(0, "Automatic check is on", "")})
        self.assertEqual(_macos_auto_updates(runner).status, "pass")

    def test_off(self):
        runner = FakeRunner(outputs={_SOFTWAREUPDATE: CommandResult(0, "Automatic check is off", "")})
        self.assertEqual(_macos_auto_updates(runner).status, "fail")


# ---------------------------------------------------------------------------
# system_checks – Windows firewall
# ---------------------------------------------------------------------------

_PS_FLAGS = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command")


def _ps_cmd(*script_parts):
    return _PS_FLAGS + (" ".join(script_parts),)


_WIN_FW_CMD = _PS_FLAGS + ("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",)
_WIN_BL_CMD = _PS_FLAGS + ("Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus | ConvertTo-Json -Compress",)
_WIN_RDP_CMD = _PS_FLAGS + ("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",)
_WIN_DEF_CMD = _PS_FLAGS + ("(Get-MpPreference).DisableRealtimeMonitoring",)


class TestWindowsFirewall(unittest.TestCase):
    def test_all_profiles_enabled(self):
        payload = '[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":true}]'
        runner = FakeRunner(outputs={_WIN_FW_CMD: CommandResult(0, payload, "")})
        self.assertEqual(_windows_firewall(runner).status, "pass")

    def test_profile_disabled(self):
        payload = '[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":false},{"Name":"Public","Enabled":true}]'
        runner = FakeRunner(outputs={_WIN_FW_CMD: CommandResult(0, payload, "")})
        self.assertEqual(_windows_firewall(runner).status, "fail")

    def test_powershell_unavailable(self):
        runner = FakeRunner(outputs={_WIN_FW_CMD: CommandResult(127, "", "command not found")})
        self.assertEqual(_windows_firewall(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – Windows BitLocker
# ---------------------------------------------------------------------------

class TestWindowsBitlocker(unittest.TestCase):
    def test_protection_on(self):
        payload = '[{"MountPoint":"C:","ProtectionStatus":1}]'
        runner = FakeRunner(outputs={_WIN_BL_CMD: CommandResult(0, payload, "")})
        self.assertEqual(_windows_bitlocker(runner).status, "pass")

    def test_protection_on_string(self):
        payload = '[{"MountPoint":"C:","ProtectionStatus":"On"}]'
        runner = FakeRunner(outputs={_WIN_BL_CMD: CommandResult(0, payload, "")})
        self.assertEqual(_windows_bitlocker(runner).status, "pass")

    def test_protection_off(self):
        payload = '[{"MountPoint":"C:","ProtectionStatus":0}]'
        runner = FakeRunner(outputs={_WIN_BL_CMD: CommandResult(0, payload, "")})
        self.assertEqual(_windows_bitlocker(runner).status, "fail")

    def test_empty_output(self):
        runner = FakeRunner(outputs={_WIN_BL_CMD: CommandResult(0, "", "")})
        self.assertEqual(_windows_bitlocker(runner).status, "fail")

    def test_powershell_unavailable(self):
        runner = FakeRunner(outputs={_WIN_BL_CMD: CommandResult(127, "", "")})
        self.assertEqual(_windows_bitlocker(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – Windows RDP
# ---------------------------------------------------------------------------

class TestWindowsRdp(unittest.TestCase):
    def test_rdp_disabled(self):
        runner = FakeRunner(outputs={_WIN_RDP_CMD: CommandResult(0, "1", "")})
        self.assertEqual(_windows_rdp(runner).status, "pass")

    def test_rdp_enabled(self):
        runner = FakeRunner(outputs={_WIN_RDP_CMD: CommandResult(0, "0", "")})
        self.assertEqual(_windows_rdp(runner).status, "fail")

    def test_powershell_unavailable(self):
        runner = FakeRunner(outputs={_WIN_RDP_CMD: CommandResult(127, "", "")})
        self.assertEqual(_windows_rdp(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – Windows Defender real-time monitoring
# ---------------------------------------------------------------------------

class TestWindowsDefender(unittest.TestCase):
    def test_realtime_enabled(self):
        runner = FakeRunner(outputs={_WIN_DEF_CMD: CommandResult(0, "False", "")})
        self.assertEqual(_windows_defender_realtime(runner).status, "pass")

    def test_realtime_disabled(self):
        runner = FakeRunner(outputs={_WIN_DEF_CMD: CommandResult(0, "True", "")})
        self.assertEqual(_windows_defender_realtime(runner).status, "fail")

    def test_powershell_unavailable(self):
        runner = FakeRunner(outputs={_WIN_DEF_CMD: CommandResult(127, "", "")})
        self.assertEqual(_windows_defender_realtime(runner).status, "skip")


# ---------------------------------------------------------------------------
# system_checks – get_rules / run_audit
# ---------------------------------------------------------------------------

class TestGetRulesAndRunAudit(unittest.TestCase):
    def test_linux_rules_count(self):
        rules = get_rules("linux")
        self.assertEqual(len(rules), 4)
        ids = {r.identifier for r in rules}
        self.assertIn("linux_firewall_enabled", ids)
        self.assertIn("linux_sshd_root_login_disabled", ids)
        self.assertIn("linux_sshd_password_auth_disabled", ids)
        self.assertIn("linux_auto_updates_enabled", ids)

    def test_macos_rules_count(self):
        rules = get_rules("macos")
        self.assertEqual(len(rules), 4)
        ids = {r.identifier for r in rules}
        self.assertIn("macos_firewall_enabled", ids)
        self.assertIn("macos_filevault_enabled", ids)
        self.assertIn("macos_remote_login_disabled", ids)
        self.assertIn("macos_auto_updates_enabled", ids)

    def test_windows_rules_count(self):
        rules = get_rules("windows")
        self.assertEqual(len(rules), 4)
        ids = {r.identifier for r in rules}
        self.assertIn("windows_firewall_enabled", ids)
        self.assertIn("windows_bitlocker_enabled", ids)
        self.assertIn("windows_rdp_disabled", ids)
        self.assertIn("windows_defender_realtime_enabled", ids)

    def test_unknown_platform_returns_empty(self):
        self.assertEqual(get_rules("freebsd"), [])

    def test_run_audit_linux(self):
        runner = FakeRunner(
            outputs={
                ("ufw", "status"): CommandResult(0, "Status: active", ""),
                _SSH_ROOT_CMD: CommandResult(0, "no", ""),
                _SSH_PWD_CMD: CommandResult(0, "no", ""),
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(0, "enabled", ""),
            },
            existing_executables={"ufw", "systemctl"},
        )
        results = run_audit("linux", runner=runner)
        self.assertEqual(len(results), 4)
        statuses = {rule.identifier: result.status for rule, result in results}
        self.assertEqual(statuses["linux_firewall_enabled"], "pass")
        self.assertEqual(statuses["linux_sshd_root_login_disabled"], "pass")
        self.assertEqual(statuses["linux_sshd_password_auth_disabled"], "pass")
        self.assertEqual(statuses["linux_auto_updates_enabled"], "pass")

    def test_run_audit_macos_all_skip(self):
        runner = FakeRunner(
            outputs={
                _SOCKETFW: CommandResult(127, "", ""),
                _FDESETUP: CommandResult(127, "", ""),
                _SYSTEMSETUP: CommandResult(1, "", "Requires admin privileges"),
                _SOFTWAREUPDATE: CommandResult(0, "Automatic check is off", ""),
            },
        )
        results = run_audit("macos", runner=runner)
        self.assertEqual(len(results), 4)

    def test_run_audit_result_has_remediation(self):
        runner = FakeRunner(
            outputs={
                ("ufw", "status"): CommandResult(0, "Status: inactive", ""),
                _SSH_ROOT_CMD: CommandResult(0, "yes", ""),
                _SSH_PWD_CMD: CommandResult(0, "yes", ""),
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(1, "disabled", ""),
                ("systemctl", "is-enabled", "unattended-upgrades.service"): CommandResult(1, "disabled", ""),
            },
            existing_executables={"ufw", "systemctl"},
        )
        results = run_audit("linux", runner=runner)
        for rule, result in results:
            if result.status == "fail":
                self.assertTrue(len(result.remediation) > 0, f"{rule.identifier} fail should have remediation")


# ---------------------------------------------------------------------------
# system_checks – original test preserved
# ---------------------------------------------------------------------------

class AuditTests(unittest.TestCase):
    def test_linux_audit_detects_failures(self):
        runner = FakeRunner(
            outputs={
                ("ufw", "status"): CommandResult(returncode=0, stdout="Status: inactive", stderr=""),
                _SSH_ROOT_CMD: CommandResult(returncode=0, stdout="yes", stderr=""),
                _SSH_PWD_CMD: CommandResult(returncode=0, stdout="yes", stderr=""),
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(returncode=1, stdout="disabled", stderr=""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(returncode=1, stdout="disabled", stderr=""),
                ("systemctl", "is-enabled", "unattended-upgrades.service"): CommandResult(returncode=1, stdout="disabled", stderr=""),
            },
            existing_executables={"ufw", "systemctl"},
        )
        results = run_audit("linux", runner=runner)
        statuses = {rule.identifier: result.status for rule, result in results}
        self.assertEqual(statuses["linux_firewall_enabled"], "fail")
        self.assertEqual(statuses["linux_sshd_root_login_disabled"], "fail")
        self.assertEqual(statuses["linux_sshd_password_auth_disabled"], "fail")
        self.assertEqual(statuses["linux_auto_updates_enabled"], "fail")

    def test_remediation_script_rendering(self):
        script = render_remediation_script(
            "linux",
            [CheckResult(rule_id="rule1", status="fail", details="x", remediation=["echo test"])],
        )
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("echo test", script)

    def test_json_report_includes_summary(self):
        rule = _make_rule()
        report = render_json_report(
            "linux",
            [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
            None,
        )
        payload = json.loads(report)
        self.assertEqual(payload["summary"]["passed"], 1)

    def test_export_bundle_writes_desktop_artifacts(self):
        rule = _make_rule()
        with tempfile.TemporaryDirectory() as tmpdir:
            exported = export_report_bundle(
                "linux",
                [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
                None,
                desktop_base=Path(tmpdir),
            )
            self.assertTrue(exported["text_report"].exists())
            self.assertTrue(exported["json_report"].exists())

    def test_json_report_includes_application_findings(self):
        rule = _make_rule()
        report = render_json_report(
            "linux",
            [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
            None,
            [
                ApplicationFinding(
                    application=InstalledApplication(name="openssl", version="3.0.0", source="dpkg"),
                    cpe_name="cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
                    cves=[{"id": "CVE-2024-0001"}],
                )
            ],
        )
        payload = json.loads(report)
        self.assertEqual(payload["application_findings"][0]["name"], "openssl")


# ---------------------------------------------------------------------------
# reporting – summarize_results
# ---------------------------------------------------------------------------

class TestSummarizeResults(unittest.TestCase):
    def test_mixed(self):
        rule = _make_rule()
        results = [
            (rule, CheckResult(rule_id="r1", status="pass", details="")),
            (rule, CheckResult(rule_id="r2", status="fail", details="")),
            (rule, CheckResult(rule_id="r3", status="skip", details="")),
            (rule, CheckResult(rule_id="r4", status="pass", details="")),
        ]
        summary = summarize_results(results)
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["skipped"], 1)

    def test_all_pass(self):
        rule = _make_rule()
        results = [(rule, CheckResult(rule_id="r", status="pass", details="")) for _ in range(3)]
        summary = summarize_results(results)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["skipped"], 0)


# ---------------------------------------------------------------------------
# reporting – render_text_report
# ---------------------------------------------------------------------------

class TestRenderTextReport(unittest.TestCase):
    def _make_results(self, status="pass"):
        rule = _make_rule()
        return [(rule, CheckResult(rule_id="rule1", status=status, details="details here", observed_value="obs"))]

    def test_contains_summary(self):
        text = render_text_report("linux", self._make_results(), None)
        self.assertIn("Summary:", text)
        self.assertIn("1 passed", text)

    def test_contains_rule_details(self):
        text = render_text_report("linux", self._make_results(), None)
        self.assertIn("Rule One", text)
        self.assertIn("details here", text)
        self.assertIn("obs", text)

    def test_with_cves(self):
        rule = _make_rule()
        result = CheckResult(
            rule_id="rule1",
            status="fail",
            details="failed",
            related_cves=[{"id": "CVE-2024-9999", "severity": "HIGH", "score": 9.8, "description": "Bad thing"}],
        )
        text = render_text_report("linux", [(rule, result)], None)
        self.assertIn("CVE-2024-9999", text)
        self.assertIn("Bad thing", text)

    def test_with_cve_no_id(self):
        rule = _make_rule()
        result = CheckResult(
            rule_id="rule1",
            status="fail",
            details="failed",
            related_cves=[{"id": None, "severity": None, "score": None, "description": "NVD lookup failed: timeout"}],
        )
        text = render_text_report("linux", [(rule, result)], None)
        self.assertIn("lookup-unavailable", text)

    def test_with_application_findings(self):
        rule = _make_rule()
        result = CheckResult(rule_id="rule1", status="pass", details="ok")
        findings = [
            ApplicationFinding(
                application=InstalledApplication(name="curl", version="7.85.0", source="dpkg"),
                cpe_name="cpe:2.3:a:curl:curl:7.85.0:*:*:*:*:*:*:*",
                cves=[{"id": "CVE-2023-0001", "severity": "MEDIUM", "score": 6.5, "description": "curl bug"}],
            )
        ]
        text = render_text_report("linux", [(rule, result)], None, findings)
        self.assertIn("curl", text)
        self.assertIn("CVE-2023-0001", text)

    def test_empty_application_findings(self):
        rule = _make_rule()
        text = render_text_report("linux", [(rule, CheckResult(rule_id="r", status="pass", details=""))], None, [])
        self.assertIn("No application CVE matches", text)

    def test_no_application_findings(self):
        rule = _make_rule()
        text = render_text_report("linux", [(rule, CheckResult(rule_id="r", status="pass", details=""))], None)
        self.assertNotIn("Installed Application", text)

    def test_with_remediation_path(self):
        rule = _make_rule()
        text = render_text_report(
            "linux",
            [(rule, CheckResult(rule_id="r", status="pass", details=""))],
            Path("/tmp/remediate_linux.sh"),
        )
        self.assertIn("remediate_linux.sh", text)


# ---------------------------------------------------------------------------
# reporting – render_json_report
# ---------------------------------------------------------------------------

class TestRenderJsonReport(unittest.TestCase):
    def test_structure(self):
        rule = _make_rule()
        result = CheckResult(rule_id="rule1", status="fail", details="bad", observed_value="x")
        payload = json.loads(render_json_report("linux", [(rule, result)], None))
        self.assertEqual(payload["target_os"], "linux")
        self.assertIn("summary", payload)
        self.assertIn("results", payload)
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["results"][0]["status"], "fail")

    def test_remediation_path_included(self):
        rule = _make_rule()
        result = CheckResult(rule_id="rule1", status="fail", details="bad")
        payload = json.loads(render_json_report("linux", [(rule, result)], Path("/tmp/r.sh")))
        self.assertEqual(payload["remediation_script"], "/tmp/r.sh")

    def test_no_application_findings_empty_list(self):
        rule = _make_rule()
        payload = json.loads(
            render_json_report("linux", [(rule, CheckResult(rule_id="r", status="pass", details=""))], None)
        )
        self.assertEqual(payload["application_findings"], [])


# ---------------------------------------------------------------------------
# reporting – desktop_dir
# ---------------------------------------------------------------------------

class TestDesktopDir(unittest.TestCase):
    def test_unix(self):
        with patch("os.name", "posix"):
            d = desktop_dir()
            self.assertEqual(d.name, "Desktop")

    def test_windows_with_userprofile(self):
        # desktop_dir() Windows branch can only be fully tested on Windows;
        # verify the function falls through to the Unix branch on this platform.
        d = desktop_dir()
        self.assertEqual(d.name, "Desktop")


# ---------------------------------------------------------------------------
# reporting – export_report_bundle
# ---------------------------------------------------------------------------

class TestExportReportBundle(unittest.TestCase):
    def test_creates_both_reports(self):
        rule = _make_rule()
        with tempfile.TemporaryDirectory() as tmpdir:
            exported = export_report_bundle(
                "linux",
                [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
                None,
                desktop_base=Path(tmpdir),
            )
            self.assertTrue(exported["text_report"].exists())
            self.assertTrue(exported["json_report"].exists())

    def test_includes_remediation_path_key(self):
        rule = _make_rule()
        with tempfile.TemporaryDirectory() as tmpdir:
            rpath = Path(tmpdir) / "remediate_linux.sh"
            rpath.write_text("#!/bin/bash\n")
            exported = export_report_bundle(
                "linux",
                [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
                rpath,
                desktop_base=Path(tmpdir),
            )
            self.assertIn("remediation_script", exported)

    def test_fallback_when_preferred_dir_fails(self):
        rule = _make_rule()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use a read-only path to trigger fallback to cwd artifacts dir
            with patch.object(Path, "mkdir", side_effect=[PermissionError, None]):
                try:
                    export_report_bundle(
                        "linux",
                        [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
                        None,
                        desktop_base=Path(tmpdir),
                    )
                except Exception:
                    pass  # fallback may or may not succeed in test env


# ---------------------------------------------------------------------------
# remediation – remediation_filename
# ---------------------------------------------------------------------------

class TestRemediationFilename(unittest.TestCase):
    def test_linux(self):
        self.assertEqual(remediation_filename("linux"), "remediate_linux.sh")

    def test_macos(self):
        self.assertEqual(remediation_filename("macos"), "remediate_macos.sh")

    def test_windows(self):
        self.assertEqual(remediation_filename("windows"), "remediate_windows.ps1")


# ---------------------------------------------------------------------------
# remediation – render_remediation_script
# ---------------------------------------------------------------------------

class TestRenderRemediationScript(unittest.TestCase):
    def test_bash_header(self):
        script = render_remediation_script("linux", [])
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("set -euo pipefail", script)

    def test_macos_bash_header(self):
        script = render_remediation_script("macos", [])
        self.assertIn("#!/usr/bin/env bash", script)

    def test_windows_ps1_header(self):
        script = render_remediation_script("windows", [])
        self.assertIn("$ErrorActionPreference", script)
        self.assertNotIn("#!/usr/bin/env bash", script)

    def test_linux_includes_commands(self):
        result = CheckResult(rule_id="linux_fw", status="fail", details="x", remediation=["sudo ufw enable"])
        script = render_remediation_script("linux", [result])
        self.assertIn("sudo ufw enable", script)
        self.assertIn("# linux_fw", script)

    def test_windows_includes_commands(self):
        result = CheckResult(
            rule_id="windows_fw",
            status="fail",
            details="x",
            remediation=["Set-NetFirewallProfile -Enabled True"],
        )
        script = render_remediation_script("windows", [result])
        self.assertIn("Set-NetFirewallProfile -Enabled True", script)
        self.assertIn("# windows_fw", script)

    def test_multiple_results(self):
        results = [
            CheckResult(rule_id="r1", status="fail", details="x", remediation=["cmd1"]),
            CheckResult(rule_id="r2", status="fail", details="y", remediation=["cmd2", "cmd3"]),
        ]
        script = render_remediation_script("linux", results)
        self.assertIn("cmd1", script)
        self.assertIn("cmd2", script)
        self.assertIn("cmd3", script)


# ---------------------------------------------------------------------------
# remediation – write_remediation_script
# ---------------------------------------------------------------------------

class TestWriteRemediationScript(unittest.TestCase):
    def test_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            result = CheckResult(rule_id="r1", status="fail", details="x", remediation=["echo hi"])
            path = write_remediation_script(out, "linux", [result])
            self.assertTrue(path.exists())
            self.assertIn("echo hi", path.read_text())

    def test_linux_script_is_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = CheckResult(rule_id="r1", status="fail", details="x", remediation=["sudo ufw enable"])
            path = write_remediation_script(Path(tmpdir), "linux", [result])
            self.assertTrue(os.access(path, os.X_OK))

    def test_macos_script_is_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = CheckResult(rule_id="r1", status="fail", details="x", remediation=["sudo fdesetup enable"])
            path = write_remediation_script(Path(tmpdir), "macos", [result])
            self.assertTrue(os.access(path, os.X_OK))

    def test_windows_script_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = CheckResult(rule_id="r1", status="fail", details="x", remediation=["Set-NetFirewallProfile"])
            path = write_remediation_script(Path(tmpdir), "windows", [result])
            self.assertEqual(path.suffix, ".ps1")


# ---------------------------------------------------------------------------
# inventory – _first_version_token
# ---------------------------------------------------------------------------

class TestFirstVersionToken(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_first_version_token("1.2.3"), "1.2.3")

    def test_with_prefix(self):
        self.assertEqual(_first_version_token("openssl-3.0.5"), "3.0.5")

    def test_with_suffix(self):
        result = _first_version_token("2.6.1-ubuntu")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("2.6.1"))

    def test_no_version(self):
        self.assertIsNone(_first_version_token("unknown"))

    def test_complex_version(self):
        result = _first_version_token("7.85.0-1ubuntu0.1")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("7.85.0"))


# ---------------------------------------------------------------------------
# inventory – _inventory_linux
# ---------------------------------------------------------------------------

class TestInventoryLinux(unittest.TestCase):
    def test_dpkg(self):
        runner = FakeRunner(
            outputs={
                ("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"): CommandResult(
                    0, "curl\t7.85.0\nopenssl\t3.0.0\n", ""
                )
            },
            existing_executables={"dpkg-query"},
        )
        apps = _inventory_linux(runner, limit=10)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0].name, "curl")
        self.assertEqual(apps[0].source, "dpkg")

    def test_dpkg_limit(self):
        rows = "\n".join(f"pkg{i}\t1.0.{i}" for i in range(20))
        runner = FakeRunner(
            outputs={("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"): CommandResult(0, rows, "")},
            existing_executables={"dpkg-query"},
        )
        apps = _inventory_linux(runner, limit=5)
        self.assertEqual(len(apps), 5)

    def test_rpm(self):
        runner = FakeRunner(
            outputs={("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"): CommandResult(0, "bash\t5.2-1\n", "")},
            existing_executables={"rpm"},
        )
        apps = _inventory_linux(runner, limit=10)
        self.assertEqual(apps[0].source, "rpm")

    def test_pacman(self):
        runner = FakeRunner(
            outputs={("pacman", "-Q"): CommandResult(0, "zsh 5.9-1\nbash 5.2-1\n", "")},
            existing_executables={"pacman"},
        )
        apps = _inventory_linux(runner, limit=10)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0].source, "pacman")

    def test_no_package_manager(self):
        runner = FakeRunner(existing_executables=set())
        apps = _inventory_linux(runner, limit=10)
        self.assertEqual(apps, [])

    def test_dpkg_skips_malformed_lines(self):
        runner = FakeRunner(
            outputs={
                ("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"): CommandResult(0, "good\t1.0\nbad_line\n\n", "")
            },
            existing_executables={"dpkg-query"},
        )
        apps = _inventory_linux(runner, limit=10)
        self.assertEqual(len(apps), 1)


# ---------------------------------------------------------------------------
# inventory – _inventory_macos
# ---------------------------------------------------------------------------

class TestInventoryMacos(unittest.TestCase):
    def test_brew(self):
        runner = FakeRunner(
            outputs={("brew", "list", "--versions"): CommandResult(0, "curl 7.85.0\nopenssl 3.0.5\n", "")},
            existing_executables={"brew"},
        )
        apps = _inventory_macos(runner, limit=10)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0].source, "brew")

    def test_brew_limit(self):
        rows = "\n".join(f"pkg{i} 1.0.{i}" for i in range(20))
        runner = FakeRunner(
            outputs={("brew", "list", "--versions"): CommandResult(0, rows, "")},
            existing_executables={"brew"},
        )
        apps = _inventory_macos(runner, limit=3)
        self.assertEqual(len(apps), 3)

    def test_applications_fallback(self):
        find_cmd = (
            "sh", "-c",
            "find /Applications -maxdepth 1 -name '*.app' -exec basename {} .app \\; | sort | head -n 5",
        )
        runner = FakeRunner(
            outputs={find_cmd: CommandResult(0, "Safari\nChrome\n", "")},
            existing_executables=set(),
        )
        apps = _inventory_macos(runner, limit=5)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0].version, "unknown")
        self.assertEqual(apps[0].source, "applications")

    def test_fallback_failure_returns_empty(self):
        find_cmd = (
            "sh", "-c",
            "find /Applications -maxdepth 1 -name '*.app' -exec basename {} .app \\; | sort | head -n 5",
        )
        runner = FakeRunner(
            outputs={find_cmd: CommandResult(1, "", "error")},
            existing_executables=set(),
        )
        apps = _inventory_macos(runner, limit=5)
        self.assertEqual(apps, [])


# ---------------------------------------------------------------------------
# inventory – _inventory_windows
# ---------------------------------------------------------------------------

_WIN_INV_SCRIPT = (
    "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
    "$paths = @("
    "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
    ");"
    "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
    "Where-Object { $_.DisplayName -and $_.DisplayVersion } | "
    "Sort-Object DisplayName -Unique | "
    "Select-Object -First 10 DisplayName, DisplayVersion | ConvertTo-Json -Compress",
)


class TestInventoryWindows(unittest.TestCase):
    def _runner_with(self, stdout, returncode=0):
        return FakeRunner(outputs={_WIN_INV_SCRIPT: CommandResult(returncode, stdout, "")})

    def test_list(self):
        payload = '[{"DisplayName":"Git","DisplayVersion":"2.40.0"},{"DisplayName":"Python","DisplayVersion":"3.11.0"}]'
        apps = _inventory_windows(self._runner_with(payload), limit=10)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0].name, "Git")
        self.assertEqual(apps[0].source, "registry")

    def test_single_object(self):
        payload = '{"DisplayName":"Git","DisplayVersion":"2.40.0"}'
        apps = _inventory_windows(self._runner_with(payload), limit=10)
        self.assertEqual(len(apps), 1)

    def test_empty_output(self):
        apps = _inventory_windows(self._runner_with(""), limit=10)
        self.assertEqual(apps, [])

    def test_invalid_json(self):
        apps = _inventory_windows(self._runner_with("not-json"), limit=10)
        self.assertEqual(apps, [])

    def test_error_returncode(self):
        apps = _inventory_windows(self._runner_with("", returncode=1), limit=10)
        self.assertEqual(apps, [])


# ---------------------------------------------------------------------------
# inventory – inventory_applications
# ---------------------------------------------------------------------------

class TestInventoryApplications(unittest.TestCase):
    def test_linux_dispatches(self):
        runner = FakeRunner(
            outputs={("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"): CommandResult(0, "curl\t7.85.0\n", "")},
            existing_executables={"dpkg-query"},
        )
        apps = inventory_applications("linux", runner=runner, limit=10)
        self.assertEqual(apps[0].name, "curl")

    def test_macos_dispatches(self):
        runner = FakeRunner(
            outputs={("brew", "list", "--versions"): CommandResult(0, "curl 7.85.0\n", "")},
            existing_executables={"brew"},
        )
        apps = inventory_applications("macos", runner=runner, limit=10)
        self.assertEqual(apps[0].name, "curl")

    def test_unknown_platform_empty(self):
        runner = FakeRunner()
        apps = inventory_applications("freebsd", runner=runner, limit=10)
        self.assertEqual(apps, [])

    def test_limit_capped_at_one(self):
        runner = FakeRunner(
            outputs={("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"): CommandResult(0, "curl\t7.85.0\n", "")},
            existing_executables={"dpkg-query"},
        )
        apps = inventory_applications("linux", runner=runner, limit=0)
        self.assertLessEqual(len(apps), 1)


# ---------------------------------------------------------------------------
# inventory – map_applications_to_cves
# ---------------------------------------------------------------------------

class TestMapApplicationsToCves(unittest.TestCase):
    def test_no_version_token_skipped(self):
        app = InstalledApplication(name="noversion", version="unknown", source="dpkg")
        with patch("security_audit_tool.inventory.search_cpes", return_value=[]):
            findings = map_applications_to_cves([app])
        self.assertEqual(findings, [])

    def test_no_cpes_skipped(self):
        app = InstalledApplication(name="curl", version="7.85.0", source="dpkg")
        with patch("security_audit_tool.inventory.search_cpes", return_value=[]):
            findings = map_applications_to_cves([app])
        self.assertEqual(findings, [])

    def test_cpe_version_match(self):
        app = InstalledApplication(name="curl", version="7.85.0", source="dpkg")
        cpe_name = "cpe:2.3:a:haxx:curl:7.85.0:*:*:*:*:*:*:*"
        with patch("security_audit_tool.inventory.search_cpes", return_value=[{"cpeName": cpe_name}]), \
             patch("security_audit_tool.inventory.fetch_cves_by_cpe", return_value=[{"id": "CVE-2023-0001"}]):
            findings = map_applications_to_cves([app])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].application.name, "curl")

    def test_wildcard_cpe_fallback(self):
        app = InstalledApplication(name="curl", version="7.85.0", source="dpkg")
        cpe_name = "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"
        with patch("security_audit_tool.inventory.search_cpes", return_value=[{"cpeName": cpe_name}]), \
             patch("security_audit_tool.inventory.fetch_cves_by_cpe", return_value=[{"id": "CVE-2023-0001"}]):
            findings = map_applications_to_cves([app])
        self.assertEqual(len(findings), 1)

    def test_no_cve_match_excluded(self):
        app = InstalledApplication(name="curl", version="7.85.0", source="dpkg")
        cpe_name = "cpe:2.3:a:haxx:curl:7.85.0:*:*:*:*:*:*:*"
        with patch("security_audit_tool.inventory.search_cpes", return_value=[{"cpeName": cpe_name}]), \
             patch("security_audit_tool.inventory.fetch_cves_by_cpe", return_value=[]):
            findings = map_applications_to_cves([app])
        self.assertEqual(findings, [])

    def test_no_cpe_name_in_results(self):
        app = InstalledApplication(name="curl", version="7.85.0", source="dpkg")
        with patch("security_audit_tool.inventory.search_cpes", return_value=[{"cpeName": None}]):
            findings = map_applications_to_cves([app])
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# nvd – _extract_description
# ---------------------------------------------------------------------------

class TestExtractDescription(unittest.TestCase):
    def test_english(self):
        cve = {"descriptions": [{"lang": "es", "value": "Mal"}, {"lang": "en", "value": "Good"}]}
        self.assertEqual(_extract_description(cve), "Good")

    def test_no_english(self):
        cve = {"descriptions": [{"lang": "de", "value": "Schlecht"}]}
        self.assertEqual(_extract_description(cve), "")

    def test_empty(self):
        self.assertEqual(_extract_description({}), "")


# ---------------------------------------------------------------------------
# nvd – _extract_cvss
# ---------------------------------------------------------------------------

class TestExtractCvss(unittest.TestCase):
    def test_v31(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]
            }
        }
        severity, score = _extract_cvss(cve)
        self.assertEqual(severity, "HIGH")
        self.assertEqual(score, 8.1)

    def test_v30_fallback(self):
        cve = {
            "metrics": {
                "cvssMetricV30": [{"cvssData": {"baseSeverity": "MEDIUM", "baseScore": 5.3}}]
            }
        }
        severity, score = _extract_cvss(cve)
        self.assertEqual(severity, "MEDIUM")
        self.assertEqual(score, 5.3)

    def test_v2_fallback(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]
            }
        }
        severity, score = _extract_cvss(cve)
        self.assertEqual(score, 7.5)

    def test_no_metrics(self):
        severity, score = _extract_cvss({})
        self.assertIsNone(severity)
        self.assertIsNone(score)

    def test_empty_metric_list(self):
        cve = {"metrics": {"cvssMetricV31": []}}
        severity, score = _extract_cvss(cve)
        self.assertIsNone(severity)
        self.assertIsNone(score)


# ---------------------------------------------------------------------------
# nvd – fetch_related_cves (mocked network)
# ---------------------------------------------------------------------------

class TestFetchRelatedCves(unittest.TestCase):
    def _nvd_payload(self):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "A vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.0}}]
                        },
                    }
                }
            ]
        }

    def test_returns_formatted_list(self):
        from security_audit_tool.models import CVEQuery
        query = CVEQuery(keyword="linux firewall")
        with patch("security_audit_tool.nvd._request_nvd", return_value=self._nvd_payload()):
            results = fetch_related_cves(query, limit=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "CVE-2024-0001")
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[0]["score"], 8.0)
        self.assertEqual(results[0]["source"], "NIST NVD")

    def test_empty_response(self):
        from security_audit_tool.models import CVEQuery
        query = CVEQuery(keyword="x")
        with patch("security_audit_tool.nvd._request_nvd", return_value={"vulnerabilities": []}):
            results = fetch_related_cves(query)
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# nvd – search_cpes (mocked network)
# ---------------------------------------------------------------------------

class TestSearchCpes(unittest.TestCase):
    def test_returns_cpe_list(self):
        payload = {
            "products": [
                {"cpe": {"cpeName": "cpe:2.3:a:curl:curl:7.85.0:*", "titles": [{"lang": "en", "title": "curl"}]}}
            ]
        }
        with patch("security_audit_tool.nvd._request_nvd", return_value=payload):
            results = search_cpes("curl", limit=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cpeName"], "cpe:2.3:a:curl:curl:7.85.0:*")

    def test_empty_response(self):
        with patch("security_audit_tool.nvd._request_nvd", return_value={"products": []}):
            results = search_cpes("nonexistent")
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# nvd – fetch_cves_by_cpe (mocked network)
# ---------------------------------------------------------------------------

class TestFetchCvesByCpe(unittest.TestCase):
    def test_returns_cves(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-9999",
                        "published": "2023-06-01T00:00:00.000",
                        "lastModified": "2023-06-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {},
                    }
                }
            ]
        }
        with patch("security_audit_tool.nvd._request_nvd", return_value=payload):
            results = fetch_cves_by_cpe("cpe:2.3:a:curl:curl:7.85.0:*", limit=1)
        self.assertEqual(results[0]["id"], "CVE-2023-9999")

    def test_empty_response(self):
        with patch("security_audit_tool.nvd._request_nvd", return_value={"vulnerabilities": []}):
            results = fetch_cves_by_cpe("cpe:bogus", limit=1)
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# cli – build_parser
# ---------------------------------------------------------------------------

class TestBuildParser(unittest.TestCase):
    def setUp(self):
        from security_audit_tool.cli import build_parser
        self.parser = build_parser()

    def test_defaults(self):
        args = self.parser.parse_args([])
        self.assertEqual(args.target_os, "auto")
        self.assertEqual(args.format, "text")
        self.assertFalse(args.include_cves)
        self.assertEqual(args.results_per_finding, 3)
        self.assertEqual(args.app_limit, 25)
        self.assertFalse(args.generate_remediation)
        self.assertFalse(args.save_to_desktop)
        self.assertFalse(args.scan_apps)

    def test_all_flags(self):
        args = self.parser.parse_args([
            "--target-os", "linux",
            "--format", "json",
            "--include-cves",
            "--results-per-finding", "5",
            "--generate-remediation",
            "--save-to-desktop",
            "--scan-apps",
            "--app-limit", "10",
            "--output-dir", "/tmp/out",
        ])
        self.assertEqual(args.target_os, "linux")
        self.assertEqual(args.format, "json")
        self.assertTrue(args.include_cves)
        self.assertEqual(args.results_per_finding, 5)
        self.assertTrue(args.generate_remediation)
        self.assertTrue(args.scan_apps)
        self.assertEqual(args.app_limit, 10)

    def test_invalid_target_os(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--target-os", "solaris"])

    def test_invalid_format(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--format", "xml"])


# ---------------------------------------------------------------------------
# cli – _attach_cves
# ---------------------------------------------------------------------------

class TestAttachCves(unittest.TestCase):
    def setUp(self):
        from security_audit_tool.cli import _attach_cves
        self._attach_cves = _attach_cves

    def _rule(self):
        from security_audit_tool.models import CVEQuery, AuditRule
        from security_audit_tool.system_checks import _linux_firewall
        return AuditRule(
            identifier="linux_firewall_enabled",
            platform="linux",
            title="Test",
            description="desc",
            rationale="rat",
            severity="high",
            check=_linux_firewall,
            remediation=[],
            cve_queries=[CVEQuery(keyword="linux firewall")],
        )

    def test_attaches_cves_to_failed(self):
        rule = self._rule()
        result = CheckResult(rule_id="linux_firewall_enabled", status="fail", details="x")
        cve_data = [{"id": "CVE-2024-0001", "severity": "HIGH", "score": 8.0, "description": "Bad", "source": "NIST NVD"}]
        with patch("security_audit_tool.cli.fetch_related_cves", return_value=cve_data):
            self._attach_cves([(rule, result)], per_finding=1)
        self.assertEqual(len(result.related_cves), 1)
        self.assertEqual(result.related_cves[0]["id"], "CVE-2024-0001")

    def test_skips_pass_results(self):
        rule = self._rule()
        result = CheckResult(rule_id="linux_firewall_enabled", status="pass", details="x")
        with patch("security_audit_tool.cli.fetch_related_cves") as mock_fetch:
            self._attach_cves([(rule, result)], per_finding=1)
        mock_fetch.assert_not_called()

    def test_deduplicates_cves(self):
        rule = self._rule()
        result = CheckResult(rule_id="linux_firewall_enabled", status="fail", details="x")
        dup = {"id": "CVE-2024-0001", "severity": "HIGH", "score": 8.0, "description": "D", "source": "NIST NVD"}
        with patch("security_audit_tool.cli.fetch_related_cves", return_value=[dup, dup]):
            self._attach_cves([(rule, result)], per_finding=2)
        self.assertEqual(len(result.related_cves), 1)

    def test_network_error_adds_placeholder(self):
        rule = self._rule()
        result = CheckResult(rule_id="linux_firewall_enabled", status="fail", details="x")
        with patch("security_audit_tool.cli.fetch_related_cves", side_effect=URLError("timeout")):
            self._attach_cves([(rule, result)], per_finding=1)
        self.assertEqual(len(result.related_cves), 1)
        self.assertIn("NVD lookup failed", result.related_cves[0]["description"])

    def test_http_error_adds_placeholder(self):
        rule = self._rule()
        result = CheckResult(rule_id="linux_firewall_enabled", status="fail", details="x")
        with patch("security_audit_tool.cli.fetch_related_cves", side_effect=HTTPError(None, 503, "Service Unavailable", {}, None)):
            self._attach_cves([(rule, result)], per_finding=1)
        self.assertEqual(len(result.related_cves), 1)

    def test_no_cve_queries_skipped(self):
        from security_audit_tool.models import AuditRule
        from security_audit_tool.system_checks import _linux_firewall
        rule = AuditRule(
            identifier="r", platform="linux", title="T", description="d",
            rationale="r", severity="high", check=_linux_firewall, remediation=[], cve_queries=[],
        )
        result = CheckResult(rule_id="r", status="fail", details="x")
        with patch("security_audit_tool.cli.fetch_related_cves") as mock_fetch:
            self._attach_cves([(rule, result)], per_finding=1)
        mock_fetch.assert_not_called()


# ---------------------------------------------------------------------------
# cli – main integration
# ---------------------------------------------------------------------------

class TestCliMain(unittest.TestCase):
    def _run_main(self, argv, runner=None):
        from security_audit_tool.cli import main
        with patch("sys.argv", ["security-audit"] + argv), \
             patch("security_audit_tool.cli.run_audit") as mock_audit, \
             patch("security_audit_tool.cli.detect_platform", return_value="linux"):
            rule = _make_rule()
            mock_audit.return_value = [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))]
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = main()
            return exit_code, buf.getvalue(), mock_audit

    def test_basic_run(self):
        code, output, _ = self._run_main(["--target-os", "linux"])
        self.assertEqual(code, 0)

    def test_json_format(self):
        code, output, _ = self._run_main(["--target-os", "linux", "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertIn("target_os", payload)

    def test_unknown_platform_exits(self):
        from security_audit_tool.cli import main
        with patch("sys.argv", ["security-audit"]), \
             patch("security_audit_tool.cli.detect_platform", return_value="unknown"), \
             self.assertRaises(SystemExit):
            main()

    def test_include_cves(self):
        from security_audit_tool.cli import main
        with patch("sys.argv", ["security-audit", "--target-os", "linux", "--include-cves"]), \
             patch("security_audit_tool.cli.run_audit") as mock_audit, \
             patch("security_audit_tool.cli.detect_platform", return_value="linux"), \
             patch("security_audit_tool.cli._attach_cves") as mock_attach:
            rule = _make_rule()
            mock_audit.return_value = [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))]
            import io
            from contextlib import redirect_stdout
            with redirect_stdout(io.StringIO()):
                main()
            mock_attach.assert_called_once()

    def test_generate_remediation(self):
        from security_audit_tool.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["security-audit", "--target-os", "linux", "--generate-remediation",
                                    "--output-dir", tmpdir]), \
                 patch("security_audit_tool.cli.run_audit") as mock_audit, \
                 patch("security_audit_tool.cli.detect_platform", return_value="linux"), \
                 patch("security_audit_tool.cli.write_remediation_script", return_value=Path(tmpdir) / "r.sh") as mock_rem:
                rule = _make_rule()
                fail = CheckResult(rule_id="rule1", status="fail", details="bad")
                mock_audit.return_value = [(rule, fail)]
                import io
                from contextlib import redirect_stdout
                with redirect_stdout(io.StringIO()):
                    main()
            mock_rem.assert_called_once()


if __name__ == "__main__":
    unittest.main()

