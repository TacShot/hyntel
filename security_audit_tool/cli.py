from __future__ import annotations

import argparse
from pathlib import Path
from urllib.error import HTTPError, URLError

from .inventory import inventory_applications, map_applications_to_cves
from .models import CheckResult
from .nvd import fetch_related_cves
from .reporting import export_report_bundle, render_json_report, render_text_report
from .remediation import write_remediation_script
from .system_checks import detect_platform, run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit security configuration on Linux, macOS, or Windows hosts.",
    )
    parser.add_argument(
        "--target-os",
        choices=["auto", "linux", "macos", "windows"],
        default="auto",
        help="Platform ruleset to run. Use auto for the current host.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--include-cves",
        action="store_true",
        help="Query the NIST NVD API for related CVEs for failed checks.",
    )
    parser.add_argument(
        "--results-per-finding",
        type=int,
        default=3,
        help="How many NVD entries to return per failed finding.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="Directory for generated remediation scripts.",
    )
    parser.add_argument(
        "--generate-remediation",
        action="store_true",
        help="Generate a remediation script for failed checks.",
    )
    parser.add_argument(
        "--save-to-desktop",
        action="store_true",
        help="Save the final text and JSON reports to the current user's Desktop.",
    )
    parser.add_argument(
        "--scan-apps",
        action="store_true",
        help="Inventory installed applications and match their versions against NVD CVEs.",
    )
    parser.add_argument(
        "--app-limit",
        type=int,
        default=25,
        help="Maximum number of installed applications to inventory per run.",
    )
    return parser


def _attach_cves(results: list[tuple], per_finding: int) -> None:
    for rule, result in results:
        if result.status != "fail" or not rule.cve_queries:
            continue
        related = []
        for query in rule.cve_queries:
            try:
                related.extend(fetch_related_cves(query, limit=per_finding))
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                related.append(
                    {
                        "id": None,
                        "severity": None,
                        "score": None,
                        "published": None,
                        "description": f"NVD lookup failed: {exc}",
                        "source": "NIST NVD",
                    }
                )
                break
        seen = set()
        result.related_cves = []
        for item in related:
            key = item.get("id") or item.get("description")
            if key in seen:
                continue
            seen.add(key)
            result.related_cves.append(item)

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target_os = detect_platform() if args.target_os == "auto" else args.target_os
    if target_os == "unknown":
        parser.error("Could not detect a supported platform. Use --target-os explicitly.")

    results = run_audit(target_os)

    if args.include_cves:
        _attach_cves(results, max(1, args.results_per_finding))

    application_findings = None
    if args.scan_apps:
        applications = inventory_applications(target_os, limit=max(1, args.app_limit))
        try:
            application_findings = map_applications_to_cves(applications)
        except (HTTPError, URLError, TimeoutError, OSError):
            application_findings = []

    failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
    remediation_path = None
    if args.generate_remediation and failed_results:
        remediation_path = write_remediation_script(args.output_dir, target_os, failed_results)

    if args.save_to_desktop:
        exported = export_report_bundle(target_os, results, remediation_path, application_findings)
        print(f"Saved reports to Desktop: {exported['text_report']}")

    if args.format == "json":
        print(render_json_report(target_os, results, remediation_path, application_findings), end="")
    else:
        print(render_text_report(target_os, results, remediation_path, application_findings), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
