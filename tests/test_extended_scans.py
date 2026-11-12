from __future__ import annotations

import unittest
from unittest.mock import patch
from types import SimpleNamespace

from security_audit_tool.active_directory import verify_active_directory_config
from security_audit_tool.log_scanning import scan_security_logs


class TestLogScanning(unittest.TestCase):
    @patch("security_audit_tool.log_scanning.shutil.which", return_value=None)
    def test_linux_reports_missing_log_backend(self, _which):
        result = scan_security_logs("linux")
        self.assertFalse(result.scanned)
        self.assertTrue(result.warnings)

    @patch("security_audit_tool.log_scanning._run")
    @patch("security_audit_tool.log_scanning.shutil.which", return_value="/usr/bin/journalctl")
    def test_linux_parses_journal_json(self, _which, run):
        run.return_value = SimpleNamespace(returncode=0, stdout='{"MESSAGE":"Failed password for invalid user","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"4"}', stderr="")
        result = scan_security_logs("linux")
        self.assertEqual(len(result.events), 1)
        self.assertIn("Failed password", result.events[0].message)

    def test_unsupported_platform_is_reported(self):
        result = scan_security_logs("plan9")
        self.assertFalse(result.scanned)
        self.assertTrue(result.warnings)


class TestActiveDirectory(unittest.TestCase):
    def test_non_windows_is_explicitly_unsupported(self):
        result = verify_active_directory_config("macos")
        self.assertFalse(result.supported)
        self.assertIsNone(result.domain_joined)
        self.assertTrue(result.warnings)


if __name__ == "__main__":
    unittest.main()
