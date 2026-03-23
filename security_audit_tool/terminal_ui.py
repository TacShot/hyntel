from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError, URLError

from .cli import _attach_cves
from .inventory import inventory_applications, map_applications_to_cves
from .models import CheckResult
from .reporting import export_report_bundle, render_text_report
from .remediation import write_remediation_script
from .system_checks import detect_platform, run_audit


GREEN = "\033[92m"
AMBER = "\033[93m"
RESET = "\033[0m"


def _prompt_bool(label: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{label} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


def main() -> int:
    print(f"{GREEN}SECURITY AUDIT TERMINAL FALLBACK{RESET}")
    print("Tk GUI is unavailable on this system. Running terminal interface instead.\n")

    target_os = detect_platform()
    if target_os == "unknown":
        print("Could not detect a supported operating system.")
        return 1

    print(f"Detected OS: {target_os}")
    include_cves = _prompt_bool("Include NVD CVE lookup", False)
    generate_remediation = _prompt_bool("Generate remediation script", True)
    scan_apps = _prompt_bool("Scan installed applications for CVEs", False)

    print(f"\n{AMBER}Running audit...{RESET}\n")
    results = run_audit(target_os)

    if include_cves:
        _attach_cves(results, 3)

    application_findings = None
    if scan_apps:
        try:
            application_findings = map_applications_to_cves(inventory_applications(target_os, limit=25))
        except (HTTPError, URLError, TimeoutError, OSError):
            application_findings = []

    failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
    remediation_path = None
    if generate_remediation and failed_results:
        remediation_path = write_remediation_script(Path("artifacts"), target_os, failed_results)

    exported = export_report_bundle(target_os, results, remediation_path, application_findings)
    print(render_text_report(target_os, results, remediation_path, application_findings))
    print(f"Reports saved to: {exported['export_directory']}")
    return 0
