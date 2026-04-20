from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from .models import ApplicationFinding, InstalledApplication, OsInfo


def summarize_results(results: list[tuple]) -> dict[str, int]:
    return {
        "passed": sum(1 for _, result in results if result.status == "pass"),
        "failed": sum(1 for _, result in results if result.status == "fail"),
        "skipped": sum(1 for _, result in results if result.status == "skip"),
    }


def render_text_report(
    target_os: str,
    results: list[tuple],
    remediation_path: Path | None,
    application_findings: list[ApplicationFinding] | None = None,
    scanned_applications: list[InstalledApplication] | None = None,
    os_info: OsInfo | None = None,
) -> str:
    summary = summarize_results(results)
    lines = [f"Security audit report for {target_os}", ""]

    if os_info is not None:
        lines.append(f"OS        : {os_info.name}")
        lines.append(f"Version   : {os_info.version}")
        if os_info.build:
            lines.append(f"Build     : {os_info.build}")
        if os_info.kernel:
            lines.append(f"Kernel    : {os_info.kernel}")
        if os_info.security_patches:
            lines.append(f"Security patches ({len(os_info.security_patches)} installed):")
            for kb in os_info.security_patches:
                lines.append(f"  {kb}")
        lines.append("")

    lines.append(f"Summary: {summary['passed']} passed, {summary['failed']} failed, {summary['skipped']} skipped")
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

    if scanned_applications is not None:
        lines.append(f"Installed Applications Scanned ({len(scanned_applications)} total)")
        lines.append("")
        if scanned_applications:
            for app in scanned_applications:
                lines.append(f"  {app.name}  {app.version}  ({app.source})")
        else:
            lines.append("  No applications found.")
        lines.append("")

    if application_findings is not None:
        lines.append("Installed Application CVE Review")
        lines.append("")
        if application_findings:
            for finding in application_findings:
                app = finding.application
                lines.append(f"[APP] {app.name} {app.version} ({app.source})")
                if finding.cpe_name:
                    lines.append(f"  CPE: {finding.cpe_name}")
                for cve in finding.cves:
                    cve_id = cve.get("id") or "lookup-unavailable"
                    severity = cve.get("severity") or "unknown"
                    score = cve.get("score")
                    score_text = f", score {score}" if score is not None else ""
                    lines.append(f"  - {cve_id} ({severity}{score_text})")
                    if cve.get("description"):
                        lines.append(f"    {cve['description']}")
                lines.append("")
        else:
            lines.append("No application CVE matches found or application inventory was not requested.")
            lines.append("")
    if remediation_path:
        lines.append(f"Remediation script: {remediation_path}")
    return "\n".join(lines).rstrip() + "\n"


def render_json_report(
    target_os: str,
    results: list[tuple],
    remediation_path: Path | None,
    application_findings: list[ApplicationFinding] | None = None,
    scanned_applications: list[InstalledApplication] | None = None,
    os_info: OsInfo | None = None,
) -> str:
    payload: dict = {
        "target_os": target_os,
        "summary": summarize_results(results),
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
        "application_findings": [
            {
                "name": finding.application.name,
                "version": finding.application.version,
                "source": finding.application.source,
                "cpe_name": finding.cpe_name,
                "cves": finding.cves,
            }
            for finding in (application_findings or [])
        ],
    }
    if os_info is not None:
        payload["os_info"] = {
            "name": os_info.name,
            "version": os_info.version,
            "build": os_info.build,
            "kernel": os_info.kernel,
            "security_patches": os_info.security_patches,
        }
    if scanned_applications is not None:
        payload["scanned_applications"] = [
            {"name": app.name, "version": app.version, "source": app.source}
            for app in scanned_applications
        ]
    return json.dumps(payload, indent=2) + "\n"


def desktop_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("USERPROFILE")
        if base:
            return Path(base) / "Desktop"
    return Path.home() / "Desktop"


def export_report_bundle(
    target_os: str,
    results: list[tuple],
    remediation_path: Path | None,
    application_findings: list[ApplicationFinding] | None = None,
    desktop_base: Path | None = None,
    scanned_applications: list[InstalledApplication] | None = None,
    os_info: OsInfo | None = None,
) -> dict[str, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    preferred_base = (desktop_base or desktop_dir()) / "SecurityAuditReports"
    base_dir = preferred_base
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        base_dir = Path.cwd() / "artifacts" / "desktop_exports"
        base_dir.mkdir(parents=True, exist_ok=True)

    text_path = base_dir / f"security_audit_{target_os}_{timestamp}.txt"
    json_path = base_dir / f"security_audit_{target_os}_{timestamp}.json"

    text_path.write_text(
        render_text_report(target_os, results, remediation_path, application_findings, scanned_applications, os_info),
        encoding="utf-8",
    )
    json_path.write_text(
        render_json_report(target_os, results, remediation_path, application_findings, scanned_applications, os_info),
        encoding="utf-8",
    )

    exported = {
        "text_report": text_path,
        "json_report": json_path,
        "export_directory": base_dir,
    }
    if remediation_path:
        exported["remediation_script"] = remediation_path
    return exported
