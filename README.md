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

Bootstrap with the host package manager. The scripts accept any installed Python 3 interpreter, and if none is present they install a current Python 3 package through the native package manager:

```bash
./setup.sh
```

On Windows PowerShell:

```powershell
.\setup.ps1
```

Manual setup is also supported with any Python 3 interpreter:

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
- `setup.sh` supports `apt-get`, `pacman`, and `brew`. `setup.ps1` uses `winget`.
- The project metadata now accepts Python 3.7+.

## NVD source

The tool uses the official NIST NVD CVE API 2.0 endpoint:

- [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
