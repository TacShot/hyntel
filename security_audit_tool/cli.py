from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

from .models import CheckResult
from .nvd import fetch_related_cves
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


def _render_text_report(target_os: str, results: list[tuple], remediation_path: Path | None) -> str:
    lines = [f"Security audit report for {target_os}", ""]
    summary = {"pass": 0, "fail": 0, "skip": 0}
    for _, result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    lines.append(f"Summary: {summary['pass']} passed, {summary['fail']} failed, {summary['skip']} skipped")
    lines.append("")
    for rule, result in results:
        lines.append(f"[{result.status.upper()}] {rule.title} ({rule.severity})")
        lines.append(f"  Rule ID: {rule.identifier}")
        lines.append(f"  Details: {result.details}")
        if result.observed_value:
            lines.append(f"  Observed: {result.observed_value}")
        if result.related_cves:
            lines.append("  Related CVEs from NIST NVD:")
            for cve in result.related_cves:
                cve_id = cve.get("id") or "lookup-unavailable"
                severity = cve.get("severity") or "unknown"
                score = cve.get("score")
                score_text = f", score {score}" if score is not None else ""
                lines.append(f"    - {cve_id} ({severity}{score_text})")
                if cve.get("description"):
                    lines.append(f"      {cve['description']}")
        lines.append("")
    if remediation_path:
        lines.append(f"Remediation script: {remediation_path}")
    return "\n".join(lines).rstrip() + "\n"


def _render_json_report(target_os: str, results: list[tuple], remediation_path: Path | None) -> str:
    payload = {
        "target_os": target_os,
        "summary": {
            "passed": sum(1 for _, result in results if result.status == "pass"),
            "failed": sum(1 for _, result in results if result.status == "fail"),
            "skipped": sum(1 for _, result in results if result.status == "skip"),
        },
        "results": [
            {
                "rule_id": rule.identifier,
                "title": rule.title,
                "severity": rule.severity,
                "status": result.status,
                "details": result.details,
                "observed_value": result.observed_value,
                "remediation": result.remediation,
                "related_cves": result.related_cves,
            }
            for rule, result in results
        ],
        "remediation_script": str(remediation_path) if remediation_path else None,
    }
    return json.dumps(payload, indent=2) + "\n"


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target_os = detect_platform() if args.target_os == "auto" else args.target_os
    if target_os == "unknown":
        parser.error("Could not detect a supported platform. Use --target-os explicitly.")

    results = run_audit(target_os)

    if args.include_cves:
        _attach_cves(results, max(1, args.results_per_finding))

    failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
    remediation_path = None
    if args.generate_remediation and failed_results:
        remediation_path = write_remediation_script(args.output_dir, target_os, failed_results)

    if args.format == "json":
        print(_render_json_report(target_os, results, remediation_path), end="")
    else:
        print(_render_text_report(target_os, results, remediation_path), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
