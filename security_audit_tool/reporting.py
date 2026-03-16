from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


def summarize_results(results: list[tuple]) -> dict[str, int]:
    return {
        "passed": sum(1 for _, result in results if result.status == "pass"),
        "failed": sum(1 for _, result in results if result.status == "fail"),
        "skipped": sum(1 for _, result in results if result.status == "skip"),
    }


def render_text_report(target_os: str, results: list[tuple], remediation_path: Path | None) -> str:
    summary = summarize_results(results)
    lines = [f"Security audit report for {target_os}", ""]
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
    if remediation_path:
        lines.append(f"Remediation script: {remediation_path}")
    return "\n".join(lines).rstrip() + "\n"


def render_json_report(target_os: str, results: list[tuple], remediation_path: Path | None) -> str:
    payload = {
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
    }
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
    desktop_base: Path | None = None,
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

    text_path.write_text(render_text_report(target_os, results, remediation_path), encoding="utf-8")
    json_path.write_text(render_json_report(target_os, results, remediation_path), encoding="utf-8")

    exported = {
        "text_report": text_path,
        "json_report": json_path,
        "export_directory": base_dir,
    }
    if remediation_path:
        exported["remediation_script"] = remediation_path
    return exported
