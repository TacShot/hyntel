# Hyntel Rust CLI interaction guide

## Interactive launch

Run `./audit.sh` on Linux/macOS or `.\\audit.ps1` on Windows. The first launch builds the release binary when it is missing. Running `hyntel` without flags opens the wizard.

### Wizard sequence

1. **Scan profile**
   - Baseline: platform configuration controls only.
   - Extended: baseline plus installed application and process inventory.
   - Investigation: baseline plus security event collection, process review and domain diagnostics.
   - Custom: choose individual collectors.
2. **Target ruleset** — current host, Linux, macOS or Windows. Selecting another OS runs that platform's ruleset; it does not emulate the target OS. Host-only collectors may not work against a different target.
3. **Optional enrichment and collectors** — NVD CVE context, installed applications/processes, last-24-hour logs, and Active Directory diagnostics.
4. **Compliance scope** — all mapped controls, ISO 27001, HIPAA or PCI DSS.
5. **Output** — TXT, JSON and CSV export directory.
6. **Review** — a final confirmation before any collection starts.

Inputs are validated; blank input uses the displayed default. Invalid menu choices are reprompted. Ctrl+C cancels the run. The scanner does not apply remediation automatically.

## Non-interactive mode

Use explicit flags for automation; the CLI must not prompt in pipelines:

```sh
./audit.sh --target-os auto --scan-apps --include-cves --scan-logs --verify-ad --format json --report-dir ./reports
```

Windows PowerShell:

```powershell
.\\audit.ps1 --target-os auto --scan-apps --include-cves --scan-logs --verify-ad --format json --report-dir .\\reports
```

Useful flags:
- `--target-os auto|linux|macos|windows`
- `--scan-apps` — installed applications and running process review
- `--include-cves` — related baseline CVEs and app CPE/CVE matching; requires network access
- `--scan-logs` — bounded last-24-hour security log review
- `--verify-ad` — platform-specific AD/domain diagnostics
- `--generate-remediation` — writes review-only remediation guidance
- `--standard ISO27001,HIPAA,PCI_DSS`
- `--format text|json`, `--report-dir PATH`, `--no-export`

## Interpretation and limitations

- A CVE returned from a keyword or CPE search is a candidate association, not proof of exploitability. Confirm vendor, CPE, version range, patch status and applicability.
- A custom-signed Windows driver is not automatically malicious. Unsigned driver metadata is a higher-priority signal but still requires verification.
- Process indicators are heuristics and must be triaged; do not kill processes solely because of a finding.
- Log collection may be incomplete without appropriate permissions and platform utilities.
- Domain membership and discovery checks do not replace a full AD security assessment.
- Compliance labels indicate mapped control relevance, not certification or a compliance attestation.
