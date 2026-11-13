use anyhow::Result;
use std::path::Path;
use chrono::Utc;
use crate::models::{AuditReport, AuditRule, CheckResult, Platform, InstalledApplication, ApplicationFinding, OsInfo, RunningProcess, ProcessFinding, AuditSummary};

pub fn summarize_results(results: &[(AuditRule, CheckResult)]) -> AuditSummary {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for (_, result) in results {
        match result.status {
            crate::models::CheckStatus::Pass => passed += 1,
            crate::models::CheckStatus::Fail => failed += 1,
            crate::models::CheckStatus::Skip => skipped += 1,
        }
    }
    AuditSummary { passed, failed, skipped }
}

pub fn render_text_report(report: &AuditReport) -> String {
    let summary = summarize_results(&report.results);
    let mut lines = vec![];

    lines.push(format!("Security audit report for {}", platform_to_str(&report.target_platform)));
    lines.push("".to_string());

    lines.push(format!("OS: {}", report.os_info.name));
    lines.push(format!("Version: {}", report.os_info.version));
    if let Some(arch) = &report.os_info.architecture {
        lines.push(format!("Arch: {}", arch));
    }
    if let Some(build) = &report.os_info.build {
        lines.push(format!("Build: {}", build));
    }
    if let Some(kernel) = &report.os_info.kernel {
        lines.push(format!("Kernel: {}", kernel));
    }
    if !report.os_info.security_patches.is_empty() {
        lines.push(format!("Security patches ({}):", report.os_info.security_patches.len()));
        for patch in &report.os_info.security_patches {
            lines.push(format!("  {}", patch));
        }
    }
    lines.push("".to_string());

    lines.push(format!("Summary: {} passed, {} failed, {} skipped", summary.passed, summary.failed, summary.skipped));
    lines.push("".to_string());

    for (rule, result) in &report.results {
        let status_str = match result.status {
            crate::models::CheckStatus::Pass => "PASS",
            crate::models::CheckStatus::Fail => "FAIL",
            crate::models::CheckStatus::Skip => "SKIP",
        };
        lines.push(format!("[{}] {} ({:?})", status_str, rule.title, rule.severity));
        lines.push(format!("  Rule ID: {}", rule.id));
        if !rule.standards.is_empty() {
            lines.push(format!("  Standards: {}", rule.standards.join(", ")));
        }
        lines.push(format!("  What we checked: {}", rule.description));
        lines.push(format!("  Why this matters: {}", rule.rationale));
        lines.push(format!("  Details: {}", result.details));
        if let Some(observed) = &result.observed_value {
            lines.push(format!("  Observed: {}", observed));
        }
        if !result.remediation.is_empty() {
            lines.push("  Recommended action:".to_string());
            for action in &result.remediation {
                lines.push(format!("    - {}", action));
            }
        }
        if !result.related_cves.is_empty() {
            lines.push("  Related CVEs from NIST NVD:".to_string());
            for cve in &result.related_cves {
                let id = cve.id.as_deref().unwrap_or("lookup-unavailable");
                let severity = cve.severity.as_deref().unwrap_or("unknown");
                let score = cve.score.map(|s| format!(", score {:.1}", s)).unwrap_or_default();
                lines.push(format!("    - {} ({}{})", id, severity, score));
                if !cve.description.is_empty() {
                    lines.push(format!("      {}", cve.description));
                }
            }
        }
        lines.push("".to_string());
    }

    if !report.scanned_applications.is_empty() {
        lines.push(format!("Installed Applications Scanned ({} total)", report.scanned_applications.len()));
        lines.push("".to_string());
        for app in &report.scanned_applications {
            lines.push(format!("  {} {} [{}]", app.name, app.version, app.source));
        }
        lines.push("".to_string());
    }

    if !report.application_findings.is_empty() {
        lines.push("Application CVE Findings:".to_string());
        lines.push("".to_string());
        for finding in &report.application_findings {
            lines.push(format!("  {} {} (CPE: {})", finding.application.name, finding.application.version, finding.cpe_name.as_deref().unwrap_or("unknown")));
            for cve in &finding.cves {
                let id = cve.id.as_deref().unwrap_or("unknown");
                let severity = cve.severity.as_deref().unwrap_or("unknown");
                lines.push(format!("    - {} ({})", id, severity));
            }
        }
        lines.push("".to_string());
    }

    if !report.scanned_processes.is_empty() {
        lines.push(format!("Running Processes Scanned ({} total)", report.scanned_processes.len()));
        lines.push("".to_string());
        for proc in &report.scanned_processes {
            let exe = proc.executable.as_deref().unwrap_or("unknown");
            lines.push(format!("  PID {}: {} [{}]", proc.pid, proc.name, exe));
        }
        lines.push("".to_string());
    }

    if !report.process_findings.is_empty() {
        lines.push("Process Findings:".to_string());
        lines.push("".to_string());
        for finding in &report.process_findings {
            lines.push(format!("  PID {}: {} ({:?})", finding.process.pid, finding.process.name, finding.severity));
            for reason in &finding.reasons {
                lines.push(format!("    - {}", reason));
            }
            if let Some(action) = &finding.recommended_action {
                lines.push(format!("    Action: {}", action));
            }
        }
        lines.push("".to_string());
    }

    if let Some(remediation_path) = &report.remediation_path {
        lines.push(format!("Remediation script: {}", remediation_path));
        lines.push("".to_string());
    }

    // System logs
    if !report.system_logs.is_empty() {
        lines.push("System Logs:".to_string());
        lines.push("".to_string());
        for log in &report.system_logs {
            lines.push(format!("  [{}] {} {}: {}", log.timestamp.format("%Y-%m-%d %H:%M:%S"), log.level, log.source, log.message));
            if let Some(unit) = &log.unit {
                lines.push(format!("    Unit: {}", unit));
            }
            if let Some(pid) = log.pid {
                lines.push(format!("    PID: {}", pid));
            }
            if let Some(user) = &log.user {
                lines.push(format!("    User: {}", user));
            }
        }
        lines.push("".to_string());
    }

    // AD findings
    if !report.ad_findings.is_empty() {
        lines.push("Active Directory Findings:".to_string());
        lines.push("".to_string());
        for finding in &report.ad_findings {
            lines.push(format!("[{:?}] {} ({})", finding.severity, finding.title, finding.finding_type));
            lines.push(format!("  Target: {}", finding.target));
            lines.push(format!("  Description: {}", finding.description));
            lines.push(format!("  Details: {}", finding.details));
            if !finding.remediation.is_empty() {
                lines.push("  Remediation:".to_string());
                for action in &finding.remediation {
                    lines.push(format!("    - {}", action));
                }
            }
            lines.push("".to_string());
        }
    }

    lines.join("\n")
}

pub fn render_json_report(report: &AuditReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

pub fn render_csv_report(report: &AuditReport) -> String {
    let mut lines = vec![
        "type,rule_id,title,severity,status,details,observed_value,remediation,related_cves,standards,name,version,source,pid,executable,command_line,finding_severity,finding_reasons,recommended_action".to_string()
    ];

    // Audit findings
    for (rule, result) in &report.results {
        let status = match result.status {
            crate::models::CheckStatus::Pass => "pass",
            crate::models::CheckStatus::Fail => "fail",
            crate::models::CheckStatus::Skip => "skip",
        };
        let remediation = result.remediation.join("; ");
        let cves = result.related_cves.iter()
            .map(|c| c.id.as_deref().unwrap_or("unknown"))
            .collect::<Vec<_>>()
            .join("; ");
        let standards = rule.standards.join("; ");
        let observed = result.observed_value.as_deref().unwrap_or("");
        let details = result.details.replace(',', ";").replace('\n', " ");

        lines.push(format!(
            "\"{}\",\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",,,,,,,,,",
            "audit", rule.id, rule.title, rule.severity, status, details, observed, remediation, cves, standards
        ));
    }

    // Scanned applications
    for app in &report.scanned_applications {
        lines.push(format!(
            "\"{}\",,,,,,,,,,\"{}\",\"{}\",\"{}\",,,,,,,",
            "application", app.name, app.version, app.source
        ));
    }

    // Scanned processes
    for proc in &report.scanned_processes {
        let exe = proc.executable.as_deref().unwrap_or("");
        let cmd = proc.command_line.as_deref().unwrap_or("");
        lines.push(format!(
            "\"{}\",,,,,,,,,,,,\"{}\",\"{}\",\"{}\",,,,",
            "process", proc.pid, exe, cmd
        ));
    }

    // Process findings
    for finding in &report.process_findings {
        let reasons = finding.reasons.join("; ");
        let action = finding.recommended_action.as_deref().unwrap_or("");
        lines.push(format!(
            "\"{}\",,,,,,,,,,,,,,,,\"{:?}\",\"{}\",\"{}\"",
            "process_finding", finding.severity, reasons, action
        ));
    }

    // Application findings
    for finding in &report.application_findings {
        let cpes = finding.cpe_name.as_deref().unwrap_or("");
        let cves = finding.cves.iter()
            .map(|c| c.id.as_deref().unwrap_or("unknown"))
            .collect::<Vec<_>>()
            .join("; ");
        lines.push(format!(
            "\"{}\",,,,,,,,,,\"{}\",\"{}\",\"{}\",\"{}\",,,",
            "application_finding", finding.application.name, finding.application.version, cpes, cves
        ));
    }

    lines.join("\n")
}

pub fn export_report_bundle(
    report: &AuditReport,
    output_dir: &Path,
    save_to_desktop: bool,
) -> Result<ExportPaths> {
    std::fs::create_dir_all(output_dir)?;

    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let platform_str = platform_to_str(&report.target_platform);
    let base_name = format!("hyntel_{}_{}", platform_str, timestamp);

    let text_path = output_dir.join(format!("{}.txt", base_name));
    let json_path = output_dir.join(format!("{}.json", base_name));
    let csv_path = output_dir.join(format!("{}.csv", base_name));

    std::fs::write(&text_path, render_text_report(report))?;
    std::fs::write(&json_path, render_json_report(report)?)?;
    std::fs::write(&csv_path, render_csv_report(report))?;

    let mut exported = ExportPaths {
        text_report: text_path.clone(),
        json_report: json_path.clone(),
        csv_report: csv_path.clone(),
        desktop_paths: None,
    };

    if save_to_desktop {
        if let Some(desktop) = dirs::desktop_dir() {
            let desktop_dir = desktop.join("Hyntel Reports");
            std::fs::create_dir_all(&desktop_dir)?;

            let desktop_text = desktop_dir.join(format!("{}.txt", base_name));
            let desktop_json = desktop_dir.join(format!("{}.json", base_name));
            let desktop_csv = desktop_dir.join(format!("{}.csv", base_name));

            std::fs::copy(&text_path, &desktop_text)?;
            std::fs::copy(&json_path, &desktop_json)?;
            std::fs::copy(&csv_path, &desktop_csv)?;

            exported.desktop_paths = Some(DesktopPaths {
                text_report: desktop_text,
                json_report: desktop_json,
                csv_report: desktop_csv,
            });
        }
    }

    Ok(exported)
}

#[derive(Debug, Clone)]
pub struct ExportPaths {
    pub text_report: std::path::PathBuf,
    pub json_report: std::path::PathBuf,
    pub csv_report: std::path::PathBuf,
    pub desktop_paths: Option<DesktopPaths>,
}

#[derive(Debug, Clone)]
pub struct DesktopPaths {
    pub text_report: std::path::PathBuf,
    pub json_report: std::path::PathBuf,
    pub csv_report: std::path::PathBuf,
}

fn platform_to_str(platform: &Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::MacOS => "macos",
        Platform::Windows => "windows",
        Platform::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuditReport, AuditRule, CheckResult, CheckStatus, Platform, Severity, OsInfo, CveInfo};
    use uuid::Uuid;
    use chrono::Utc;

    fn sample_report() -> AuditReport {
        AuditReport {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            target_platform: Platform::Linux,
            os_info: OsInfo {
                name: "Ubuntu".to_string(),
                version: "22.04".to_string(),
                architecture: Some("x86_64".to_string()),
                build: None,
                kernel: Some("5.15.0".to_string()),
                security_patches: vec![],
            },
            results: vec![
                (
                    AuditRule {
                        id: "test_rule".to_string(),
                        platform: Platform::Linux,
                        title: "Test Rule".to_string(),
                        description: "A test rule".to_string(),
                        rationale: "Testing".to_string(),
                        severity: Severity::High,
                        remediation: vec!["fix it".to_string()],
                        cve_queries: vec![],
                        standards: vec!["ISO27001".to_string()],
                        check: |_| Ok(CheckResult {
                            rule_id: "test_rule".to_string(),
                            status: CheckStatus::Fail,
                            details: "Test failed".to_string(),
                            observed_value: Some("bad".to_string()),
                            remediation: vec!["fix it".to_string()],
                            related_cves: vec![],
                        }),
                    },
                    CheckResult {
                        rule_id: "test_rule".to_string(),
                        status: CheckStatus::Fail,
                        details: "Test failed".to_string(),
                        observed_value: Some("bad".to_string()),
                        remediation: vec!["fix it".to_string()],
                        related_cves: vec![],
                    },
                ),
            ],
            summary: Default::default(),
            application_findings: vec![],
            scanned_applications: vec![],
            scanned_processes: vec![],
            process_findings: vec![],
            system_logs: vec![],
            ad_findings: vec![],
            remediation_path: None,
        }
    }

    #[test]
    fn test_render_text_report() {
        let report = sample_report();
        let text = render_text_report(&report);
        assert!(text.contains("Security audit report for linux"));
        assert!(text.contains("[FAIL] Test Rule"));
        assert!(text.contains("Test failed"));
    }

    #[test]
    fn test_render_json_report() {
        let report = sample_report();
        let json = render_json_report(&report).unwrap();
        assert!(json.contains("test_rule"));
    }

    #[test]
    fn test_render_csv_report() {
        let report = sample_report();
        let csv = render_csv_report(&report);
        assert!(csv.contains("rule_id,title,severity"));
        assert!(csv.contains("test_rule"));
    }
}