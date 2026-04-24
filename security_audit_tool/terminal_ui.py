from __future__ import annotations

import shutil
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

from .cli import _attach_cves
from .inventory import assess_processes, inventory_applications, inventory_running_processes, map_applications_to_cves
from .models import CheckResult, DriverInfo, OsInfo, ProcessFinding, RunningProcess
from .reporting import export_report_bundle
from .remediation import write_remediation_script
from .system_checks import detect_os_info, detect_platform, get_windows_drivers, run_audit


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_SUPPORTS_COLOUR = sys.stdout.isatty() or sys.platform == "win32"

GREEN = "\033[92m" if _SUPPORTS_COLOUR else ""
RED = "\033[91m" if _SUPPORTS_COLOUR else ""
AMBER = "\033[93m" if _SUPPORTS_COLOUR else ""
CYAN = "\033[96m" if _SUPPORTS_COLOUR else ""
BOLD = "\033[1m" if _SUPPORTS_COLOUR else ""
DIM = "\033[2m" if _SUPPORTS_COLOUR else ""
RESET = "\033[0m" if _SUPPORTS_COLOUR else ""
def _safe_print(text: str) -> None:
    try:
        print(text)
    except (UnicodeEncodeError, UnicodeDecodeError, OSError):
        ascii_text = text.encode("ascii", errors="replace").decode("ascii")
        print(ascii_text)

# ---------------------------------------------------------------------------
# Box-drawing helpers
# ---------------------------------------------------------------------------

def _term_width() -> int:
    try:
        return min(shutil.get_terminal_size().columns, 100)
    except Exception:
        return 72


def _double_box(title: str, lines: list[str], width: int | None = None) -> str:
    """Render a double-line bordered box with an optional centred title."""
    w = width or _term_width()
    inner = w - 2
    rows: list[str] = []
    if title:
        padded = f"  {title}  "
        dash = inner - len(padded)
        left = dash // 2
        right = dash - left
        rows.append("╔" + "═" * left + padded + "═" * right + "╗")
    else:
        rows.append("╔" + "═" * inner + "╗")
    for line in lines:
        content = f" {line} "
        rows.append("║" + content[:inner].ljust(inner) + "║")
    rows.append("╚" + "═" * inner + "╝")
    return "\n".join(rows)


def _single_box(title: str, lines: list[str], width: int | None = None) -> str:
    """Render a single-line bordered box with an optional left-aligned title."""
    w = width or _term_width()
    inner = w - 2
    rows: list[str] = []
    if title:
        heading = f"─ {title} "
        dash = inner - len(heading)
        rows.append("┌" + heading + "─" * max(0, dash) + "┐")
    else:
        rows.append("┌" + "─" * inner + "┐")
    for line in lines:
        content = f" {line}"
        rows.append("│" + content[:inner].ljust(inner) + "│")
    rows.append("└" + "─" * inner + "┘")
    return "\n".join(rows)


def _section_sep(width: int | None = None) -> str:
    return DIM + "─" * (width or _term_width()) + RESET


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------

def _prompt_bool(label: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        raw = input(f"  {label} [{suffix}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


def _prompt_text(label: str, default: str) -> str:
    try:
        raw = input(f"  {label} [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if raw.lower() in {"y", "yes", "n", "no"}:
        return default
    return raw or default


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _status_icon(status: str) -> str:
    if status == "pass":
        return f"{GREEN}✔{RESET}"
    if status == "fail":
        return f"{RED}✘{RESET}"
    if status == "warn":
        return f"{AMBER}⚠{RESET}"
    return f"{DIM}–{RESET}"


def _severity_colour(severity: str) -> str:
    mapping = {
        "critical": RED + BOLD,
        "high": AMBER,
        "medium": CYAN,
        "low": DIM,
    }
    return mapping.get(severity.lower(), "")


def _print_header() -> None:
    w = _term_width()
    lines = [
        "SECURITY AUDIT TERMINAL",
        "Cross-platform Security Configuration Scanner",
    ]
    _safe_print(_double_box("", lines, width=w))
    print()


def _print_os_info(info: OsInfo) -> None:
    w = _term_width()
    lines: list[str] = [
        f"OS        : {info.name}",
        f"Version   : {info.version}",
    ]
    if info.architecture:
        lines.append(f"Arch      : {info.architecture}")
    if info.build:
        lines.append(f"Build     : {info.build}")
    if info.kernel:
        lines.append(f"Kernel    : {info.kernel}")
    if info.security_patches:
        lines.append(f"Security patches ({len(info.security_patches)} installed):")
        for kb in info.security_patches[:10]:
            lines.append(f"  {kb}")
        if len(info.security_patches) > 10:
            lines.append(f"  ... and {len(info.security_patches) - 10} more")
    _safe_print(_single_box("SYSTEM INFORMATION", lines, width=w))
    print()


def _print_audit_results(results: list[tuple]) -> None:
    w = _term_width()
    lines: list[str] = []
    for rule, result in results:
        sev_col = _severity_colour(rule.severity)
        icon = _status_icon(result.status)
        status_label = result.status.upper()
        line = f"{icon} [{status_label}] {rule.title}"
        sev_str = f"[{sev_col}{rule.severity.upper()}{RESET}]"
        lines.append(f"{line}  {sev_str}")
        lines.append(f"    ↳ What we checked: {DIM}{rule.description}{RESET}")
        lines.append(f"    ↳ Why it matters : {DIM}{rule.rationale}{RESET}")
        if result.details:
            lines.append(f"    ↳ {DIM}{result.details}{RESET}")
        if result.observed_value:
            lines.append(f"    ↳ Observed: {DIM}{result.observed_value}{RESET}")
        if result.remediation:
            lines.append("    ↳ Recommended action:")
            for action in result.remediation[:3]:
                lines.append(f"      • {action}")
        if result.related_cves:
            lines.append(f"    ↳ Related CVEs:")
            for cve in result.related_cves[:3]:
                cve_id = cve.get("id") or "N/A"
                severity = cve.get("severity") or "?"
                score = cve.get("score")
                score_str = f", score {score}" if score is not None else ""
                lines.append(f"      • {cve_id} ({severity}{score_str})")
        lines.append("")

    passed = sum(1 for _, r in results if r.status == "pass")
    failed = sum(1 for _, r in results if r.status == "fail")
    warned = sum(1 for _, r in results if r.status == "warn")
    skipped = sum(1 for _, r in results if r.status == "skip")
    summary = (
        f"{GREEN}{passed} passed{RESET}  "
        f"{RED}{failed} failed{RESET}  "
        f"{AMBER}{warned} warned{RESET}  "
        f"{DIM}{skipped} skipped{RESET}"
    )
    lines.append(f"Summary: {summary}")
    _safe_print(_single_box("AUDIT RESULTS", lines, width=w))
    print()


def _print_applications(
    applications: list,
    application_findings: list | None,
) -> None:
    w = _term_width()
    lines: list[str] = []

    if not applications:
        lines.append("No applications found.")
        _safe_print(_single_box(f"INSTALLED APPLICATIONS (0 scanned)", lines, width=w))
        print()
        return

    # List all scanned apps
    lines.append(f"{'Name':<35} {'Version':<20} {'Source'}")
    lines.append("─" * min(70, w - 4))
    for app in applications:
        lines.append(f"{app.name:<35} {app.version:<20} {app.source}")

    # CVE findings summary
    if application_findings:
        lines.append("")
        lines.append(f"{AMBER}⚠ CVE matches found for {len(application_findings)} application(s):{RESET}")
        for finding in application_findings:
            app = finding.application
            lines.append(f"  {RED}•{RESET} {app.name} {app.version}")
            for cve in finding.cves[:3]:
                cve_id = cve.get("id") or "N/A"
                severity = cve.get("severity") or "?"
                score = cve.get("score")
                score_str = f", score {score}" if score is not None else ""
                lines.append(f"      {cve_id} ({severity}{score_str})")
    elif application_findings is not None:
        lines.append("")
        lines.append(f"{GREEN}✔ No CVE matches found for scanned applications.{RESET}")

    _safe_print(_single_box(f"INSTALLED APPLICATIONS ({len(applications)} scanned)", lines, width=w))
    print()


def _print_process_findings(processes: list[RunningProcess], findings: list[ProcessFinding]) -> None:
    w = _term_width()
    lines: list[str] = [f"Running processes reviewed: {len(processes)}", ""]
    if findings:
        for finding in findings[:15]:
            process = finding.process
            lines.append(f"[{finding.severity.upper()}] PID {process.pid} {process.name}")
            for reason in finding.reasons:
                lines.append(f"  Why flagged : {reason}")
            if process.executable:
                lines.append(f"  Executable  : {process.executable}")
            if process.command_line and process.command_line != process.executable:
                lines.append(f"  Command     : {process.command_line}")
            if finding.recommended_action:
                lines.append(f"  Action      : {finding.recommended_action}")
            lines.append("")
    else:
        lines.append(f"{GREEN}✔ No obviously suspicious running processes were detected.{RESET}")
    _safe_print(_single_box("RUNNING PROCESS REVIEW", lines, width=w))
    print()


def _print_driver_info(drivers: list[DriverInfo]) -> None:
    w = _term_width()
    if not drivers:
        return

    dangerous = [d for d in drivers if d.is_dangerous]
    suspicious = [d for d in drivers if d.is_suspicious and not d.is_dangerous]
    microsoft = [d for d in drivers if d.sign_type == "microsoft"]
    custom = [d for d in drivers if d.sign_type == "custom"]

    lines: list[str] = [
        f"Total drivers    : {len(drivers)}",
        f"Microsoft-signed : {GREEN}{len(microsoft)}{RESET}",
        f"Custom-signed    : {AMBER}{len(custom)}{RESET}",
        f"Unsigned         : {RED if dangerous else GREEN}{len(dangerous)}{RESET}",
        "",
    ]

    if suspicious:
        lines.append(f"{AMBER}⚠ SUSPICIOUS DRIVERS (custom-signed — review recommended):{RESET}")
        for d in suspicious[:20]:
            signer = d.signer or "unknown signer"
            lines.append(f"  → {d.name:<40} Provider: {d.provider or 'N/A'}")
            lines.append(f"    Signer: {signer}")
        if len(suspicious) > 20:
            lines.append(f"  ... and {len(suspicious) - 20} more")
        lines.append("")

    if dangerous:
        lines.append(f"{RED}⛔ DANGEROUS DRIVERS (unsigned — immediate action required):{RESET}")
        for d in dangerous[:20]:
            lines.append(f"  → {d.name:<40} INF: {d.inf_name or 'N/A'}")
            lines.append(f"    Provider: {d.provider or 'N/A'}")
        if len(dangerous) > 20:
            lines.append(f"  ... and {len(dangerous) - 20} more")
        lines.append("")

    if not suspicious and not dangerous:
        lines.append(f"{GREEN}✔ All drivers are Microsoft/WHQL-signed.{RESET}")

    _safe_print(_single_box("WINDOWS DRIVER SIGNATURES", lines, width=w))
    print()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        _print_header()
    except (UnicodeEncodeError, UnicodeDecodeError, OSError):
        # Fallback for terminals that can't render box-drawing chars
        print("=== SECURITY AUDIT TERMINAL ===\n")

    target_os = detect_platform()
    if target_os == "unknown":
        print(f"{RED}ERROR: Could not detect a supported operating system.{RESET}")
        return 1

    # OS information
    try:
        os_info = detect_os_info()
        _print_os_info(os_info)
    except Exception:
        os_info = None

    w = _term_width()

    default_report_dir = str(Path.home() / "Desktop" / "SecurityAuditReports")
    print(
        _single_box(
            "SCAN CONFIGURATION",
            [
                "Choose the scan scope and report location below.",
                "Press Enter to accept the default shown in brackets.",
                "",
                "If application inventory is enabled, the audit also reviews running processes",
                "and exports a CSV with scanned apps, concerning apps, safe apps, and process findings.",
            ],
            width=w,
        )
    )
    print()
    include_cves = _prompt_bool("Include NVD CVE lookup", False)
    generate_remediation = _prompt_bool("Generate remediation script", True)
    scan_apps = _prompt_bool("Scan installed applications and running processes", True)
    report_dir = Path(_prompt_text("Save reports to", default_report_dir)).expanduser()
    print()

    # Running audit
    print(f"{BOLD}{CYAN}⟳  Running security audit for {target_os}...{RESET}\n")

    results = run_audit(target_os)

    if include_cves:
        print(f"{DIM}  Querying NIST NVD for related CVEs...{RESET}")
        _attach_cves(results, 3)
        print()

    # Application scan
    applications: list = []
    application_findings: list | None = None
    processes: list[RunningProcess] = []
    process_findings: list[ProcessFinding] = []
    if scan_apps:
        print(f"{DIM}  Inventorying installed applications...{RESET}")
        try:
            applications = inventory_applications(target_os, limit=25)
            application_findings = map_applications_to_cves(applications)
        except (HTTPError, URLError, TimeoutError, OSError):
            application_findings = []
        print(f"{DIM}  Reviewing running processes for suspicious indicators...{RESET}")
        processes = inventory_running_processes(target_os, limit=100)
        process_findings = assess_processes(processes)
        print()

    # Windows driver scan
    drivers: list[DriverInfo] = []
    if target_os == "windows":
        from .system_checks import CommandRunner
        print(f"{DIM}  Querying Windows driver signing information...{RESET}")
        try:
            drivers = get_windows_drivers(CommandRunner())
        except Exception:
            drivers = []
        print()

    # Remediation script
    failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
    remediation_path = None
    if generate_remediation and failed_results:
        try:
            remediation_path = write_remediation_script(Path("artifacts"), target_os, failed_results)
            print(f"{GREEN}  Remediation script generated: {remediation_path}{RESET}\n")
        except Exception as exc:
            print(f"{AMBER}  Warning: could not write remediation script: {exc}{RESET}\n")

    # Display results
    _print_audit_results(results)

    if scan_apps:
        _print_applications(applications, application_findings)
        _print_process_findings(processes, process_findings)

    if drivers:
        _print_driver_info(drivers)

    # Export reports
    try:
        exported = export_report_bundle(
            target_os,
            results,
            remediation_path,
            application_findings,
            desktop_base=report_dir,
            scanned_applications=applications or None,
            os_info=os_info,
            scanned_processes=processes or None,
            process_findings=process_findings,
        )
        lines = [
            f"Text report : {exported['text_report']}",
            f"JSON report : {exported['json_report']}",
            f"CSV report  : {exported['csv_report']}",
        ]
        if remediation_path:
            lines.append(f"Remediation : {remediation_path}")
        _safe_print(_single_box("EXPORTED REPORTS", lines, width=w))
    except Exception as exc:
        print(f"{AMBER}Warning: report export failed: {exc}{RESET}")

    print()
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
