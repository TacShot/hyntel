from __future__ import annotations

import json
import os
import csv
from datetime import datetime
from pathlib import Path

from .models import ApplicationFinding, InstalledApplication, OsInfo, ProcessFinding, RunningProcess


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
    scanned_processes: list[RunningProcess] | None = None,
    process_findings: list[ProcessFinding] | None = None,
) -> str:
    summary = summarize_results(results)
    lines = [f"Security audit report for {target_os}", ""]

    if os_info is not None:
        lines.append(f"OS        : {os_info.name}")
        lines.append(f"Version   : {os_info.version}")
        if os_info.architecture:
            lines.append(f"Arch      : {os_info.architecture}")
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
        if getattr(rule, "description", None):
            lines.append(f"  What we checked: {rule.description}")
        if getattr(rule, "rationale", None):
            lines.append(f"  Why this matters: {rule.rationale}")
        lines.append(f"  Details: {result.details}")
        if result.observed_value:
            lines.append(f"  Observed: {result.observed_value}")
        if result.remediation:
            lines.append("  Recommended action:")
            for action in result.remediation:
                lines.append(f"    - {action}")
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
    if scanned_processes is not None:
        lines.append(f"Running Processes Reviewed ({len(scanned_processes)} total)")
        lines.append("")
        if scanned_processes:
            for process in scanned_processes:
                location = process.executable or process.command_line or "unknown path"
                lines.append(f"  PID {process.pid}  {process.name}  ({location})")
        else:
            lines.append("  No process data collected.")
        lines.append("")
    if process_findings is not None:
        lines.append("Suspicious Running Processes")
        lines.append("")
        if process_findings:
            for finding in process_findings:
                process = finding.process
                lines.append(f"[PROCESS] PID {process.pid} {process.name} ({finding.severity})")
                for reason in finding.reasons:
                    lines.append(f"  Why it was flagged: {reason}")
                if process.executable:
                    lines.append(f"  Executable: {process.executable}")
                if process.command_line:
                    lines.append(f"  Command line: {process.command_line}")
                if finding.recommended_action:
                    lines.append(f"  Recommended action: {finding.recommended_action}")
                lines.append("")
        else:
            lines.append("No obviously suspicious running processes were detected by the built-in heuristics.")
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
    scanned_processes: list[RunningProcess] | None = None,
    process_findings: list[ProcessFinding] | None = None,
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
        "process_findings": [
            {
                "pid": finding.process.pid,
                "name": finding.process.name,
                "executable": finding.process.executable,
                "command_line": finding.process.command_line,
                "severity": finding.severity,
                "reasons": finding.reasons,
                "recommended_action": finding.recommended_action,
            }
            for finding in (process_findings or [])
        ],
    }
    if os_info is not None:
        payload["os_info"] = {
            "name": os_info.name,
            "version": os_info.version,
            "architecture": os_info.architecture,
            "build": os_info.build,
            "kernel": os_info.kernel,
            "security_patches": os_info.security_patches,
        }
    if scanned_applications is not None:
        payload["scanned_applications"] = [
            {"name": app.name, "version": app.version, "source": app.source}
            for app in scanned_applications
        ]
    if scanned_processes is not None:
        payload["scanned_processes"] = [
            {
                "pid": process.pid,
                "name": process.name,
                "executable": process.executable,
                "command_line": process.command_line,
                "source": process.source,
            }
            for process in scanned_processes
        ]
    return json.dumps(payload, indent=2) + "\n"


def write_inventory_csv(
    csv_path: Path,
    scanned_applications: list[InstalledApplication] | None = None,
    application_findings: list[ApplicationFinding] | None = None,
    scanned_processes: list[RunningProcess] | None = None,
    process_findings: list[ProcessFinding] | None = None,
) -> None:
    concerning_keys = {
        (finding.application.name, finding.application.version, finding.application.source)
        for finding in (application_findings or [])
    }
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "section",
                "item_type",
                "name",
                "version_or_pid",
                "status",
                "source",
                "path_or_command",
                "details",
                "recommended_action",
            ]
        )
        for app in scanned_applications or []:
            key = (app.name, app.version, app.source)
            writer.writerow(["scanned_apps", "application", app.name, app.version, "scanned", app.source, "", "", ""])
            if key in concerning_keys:
                finding = next(
                    item for item in (application_findings or [])
                    if (item.application.name, item.application.version, item.application.source) == key
                )
                details = "; ".join((cve.get("id") or "lookup-unavailable") for cve in finding.cves) or "CVE matches found"
                writer.writerow(
                    [
                        "concerning_apps",
                        "application",
                        app.name,
                        app.version,
                        "concerning",
                        app.source,
                        "",
                        details,
                        "Update, patch, or uninstall the application if the reported CVEs apply.",
                    ]
                )
            else:
                writer.writerow(
                    [
                        "safe_apps",
                        "application",
                        app.name,
                        app.version,
                        "no-known-cve-match",
                        app.source,
                        "",
                        "No NVD CVE match was found for this scan.",
                        "",
                    ]
                )
        for process in scanned_processes or []:
            writer.writerow(
                [
                    "scanned_processes",
                    "process",
                    process.name,
                    str(process.pid),
                    "scanned",
                    process.source,
                    process.executable or process.command_line or "",
                    "",
                    "",
                ]
            )
        for finding in process_findings or []:
            writer.writerow(
                [
                    "concerning_processes",
                    "process",
                    finding.process.name,
                    str(finding.process.pid),
                    finding.severity,
                    finding.process.source,
                    finding.process.executable or finding.process.command_line or "",
                    "; ".join(finding.reasons),
                    finding.recommended_action or "",
                ]
            )


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
    scanned_processes: list[RunningProcess] | None = None,
    process_findings: list[ProcessFinding] | None = None,
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
    csv_path = base_dir / f"security_audit_{target_os}_{timestamp}.csv"

    text_path.write_text(
        render_text_report(
            target_os,
            results,
            remediation_path,
            application_findings,
            scanned_applications,
            os_info,
            scanned_processes,
            process_findings,
        ),
        encoding="utf-8",
    )
    json_path.write_text(
        render_json_report(
            target_os,
            results,
            remediation_path,
            application_findings,
            scanned_applications,
            os_info,
            scanned_processes,
            process_findings,
        ),
        encoding="utf-8",
    )
    write_inventory_csv(csv_path, scanned_applications, application_findings, scanned_processes, process_findings)

    exported = {
        "text_report": text_path,
        "json_report": json_path,
        "csv_report": csv_path,
        "export_directory": base_dir,
    }
    if remediation_path:
        exported["remediation_script"] = remediation_path
    return exported
