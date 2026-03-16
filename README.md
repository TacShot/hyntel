# Security Audit Tool

Cross-platform CLI for security configuration auditing on Linux, macOS, and Windows. It checks a focused set of hardening controls, optionally queries the NIST National Vulnerability Database (NVD) for related CVEs, and can generate remediation scripts for failed findings.

## Features

- Linux checks: firewall, SSH root login, SSH password authentication, automatic updates
- macOS checks: firewall, FileVault, Remote Login, automatic updates
- Windows checks: firewall, BitLocker, Remote Desktop, Defender real-time monitoring
- NIST NVD 2.0 integration for related CVE lookup
- Text or JSON reports
- Generated remediation scripts for failed findings

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

Audit the current host:

```bash
security-audit
```

Include related CVEs from NIST NVD and generate a remediation script:

```bash
security-audit --include-cves --generate-remediation
```

Produce JSON output:

```bash
security-audit --format json
```

Target a specific ruleset explicitly:

```bash
security-audit --target-os linux
security-audit --target-os macos
security-audit --target-os windows
```

## Notes

- CVE mapping is heuristic. The tool searches NVD for vulnerabilities related to the failed control area; it does not claim that a local misconfiguration itself has a CVE.
- Applying remediation still requires operator review and appropriate privileges.
- NVD API key support is available through the `NVD_API_KEY` environment variable.

## NVD source

The tool uses the official NIST NVD CVE API 2.0 endpoint:

- [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
