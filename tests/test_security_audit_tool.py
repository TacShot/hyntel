import json
import tempfile
import unittest
from pathlib import Path

from security_audit_tool.reporting import export_report_bundle, render_json_report
from security_audit_tool.models import CheckResult, CommandResult
from security_audit_tool.remediation import render_remediation_script
from security_audit_tool.system_checks import CommandRunner, run_audit


class FakeRunner(CommandRunner):
    def __init__(self, outputs):
        self.outputs = outputs

    def run(self, command):
        key = tuple(command)
        return self.outputs.get(key, CommandResult(returncode=127, stdout="", stderr="command not found"))

    def exists(self, executable):
        return executable in {"ufw", "systemctl"}


class AuditTests(unittest.TestCase):
    def test_linux_audit_detects_failures(self):
        runner = FakeRunner(
            {
                ("ufw", "status"): CommandResult(returncode=0, stdout="Status: inactive", stderr=""),
                ("sh", "-c", "test -f /etc/ssh/sshd_config && sed -n 's/^\\s*PermitRootLogin\\s\\+//Ip' /etc/ssh/sshd_config | tail -n 1"): CommandResult(returncode=0, stdout="yes", stderr=""),
                ("sh", "-c", "test -f /etc/ssh/sshd_config && sed -n 's/^\\s*PasswordAuthentication\\s\\+//Ip' /etc/ssh/sshd_config | tail -n 1"): CommandResult(returncode=0, stdout="yes", stderr=""),
                ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): CommandResult(returncode=1, stdout="disabled", stderr=""),
                ("systemctl", "is-enabled", "dnf-automatic.timer"): CommandResult(returncode=1, stdout="disabled", stderr=""),
                ("systemctl", "is-enabled", "unattended-upgrades.service"): CommandResult(returncode=1, stdout="disabled", stderr=""),
            }
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
        rule = type("Rule", (), {"identifier": "rule1", "title": "Rule", "severity": "high"})
        report = render_json_report(
            "linux",
            [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
            None,
        )
        payload = json.loads(report)
        self.assertEqual(payload["summary"]["passed"], 1)

    def test_export_bundle_writes_desktop_artifacts(self):
        rule = type("Rule", (), {"identifier": "rule1", "title": "Rule", "severity": "high"})
        with tempfile.TemporaryDirectory() as tmpdir:
            exported = export_report_bundle(
                "linux",
                [(rule, CheckResult(rule_id="rule1", status="pass", details="ok"))],
                None,
                desktop_base=Path(tmpdir),
            )
            self.assertTrue(exported["text_report"].exists())
            self.assertTrue(exported["json_report"].exists())


if __name__ == "__main__":
    unittest.main()
