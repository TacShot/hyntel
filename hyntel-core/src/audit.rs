use anyhow::Result;
use crate::models::{AuditReport, CheckResult, CheckStatus, Platform, ApplicationFinding, InstalledApplication, LogEntry, AdFinding};
use crate::checks::get_rules;
use crate::command_runner::CommandRunner;
use crate::inventory::{inventory_applications, inventory_running_processes, assess_processes};
use crate::nvd::NvdClient;
use crate::platform::{detect_platform, detect_os_info};
use crate::remediation::write_remediation_script;
use crate::reporting::export_report_bundle;
use crate::logs::collect_system_logs;
use crate::ad::scan_active_directory;

pub struct AuditEngine {
    runner: CommandRunner,
    nvd_client: Option<NvdClient>,
    standards_filter: Option<Vec<String>>,
}

impl AuditEngine {
    pub fn new(standards_filter: Option<Vec<String>>, nvd_api_key: Option<String>) -> Result<Self> {
        let nvd_client = if nvd_api_key.is_some() || std::env::var("NVD_API_KEY").is_ok() {
            Some(NvdClient::new(nvd_api_key)?)
        } else {
            None
        };

        Ok(Self {
            runner: CommandRunner::new(),
            nvd_client,
            standards_filter,
        })
    }

    pub fn run_audit(
        &self,
        target_platform: Option<Platform>,
        include_cves: bool,
        cve_limit: usize,
        generate_remediation: bool,
        scan_apps: bool,
        app_limit: usize,
        save_to_desktop: bool,
        output_dir: &std::path::Path,
        collect_logs: bool,
        log_hours: i64,
        scan_ad: bool,
    ) -> Result<AuditReport> {
        let platform = target_platform.unwrap_or_else(detect_platform);
        let os_info = detect_os_info(Some(&self.runner))?;

        let mut rules = get_rules(platform.clone());

        // Filter by standards if specified
        if let Some(standards) = &self.standards_filter {
            rules.retain(|rule| {
                if rule.standards.is_empty() {
                    true // Apply to all if no standards specified
                } else {
                    standards.iter().any(|s| rule.standards.contains(s))
                }
            });
        }

        let mut results = vec![];
        for rule in rules {
            let mut result = (rule.check)(&self.runner)?;
            result.remediation = rule.remediation.clone();
            results.push((rule, result));
        }

        // Attach CVEs to failed results
        if include_cves {
            if let Some(nvd) = &self.nvd_client {
                for (rule, result) in &mut results {
                    if result.status == CheckStatus::Fail && !rule.cve_queries.is_empty() {
                        let mut related = vec![];
                        for query in &rule.cve_queries {
                            match nvd.fetch_related_cves(query, cve_limit) {
                                Ok(mut cves) => related.append(&mut cves),
                                Err(e) => {
                                    related.push(crate::models::CveInfo {
                                        id: None,
                                        published: None,
                                        last_modified: None,
                                        severity: None,
                                        score: None,
                                        description: format!("NVD lookup failed: {}", e),
                                        source: "NIST NVD".to_string(),
                                    });
                                    break;
                                }
                            }
                        }
                        // Deduplicate
                        let mut seen = std::collections::HashSet::new();
                        result.related_cves = related.into_iter()
                            .filter(|cve| {
                                let key = cve.id.as_deref().unwrap_or(&cve.description);
                                seen.insert(key.to_string())
                            })
                            .collect();
                    }
                }
            }
        }

        // Inventory applications and scan for CVEs
        let (application_findings, scanned_applications, scanned_processes, process_findings) = if scan_apps {
            let apps = inventory_applications(platform.clone(), &self.runner, app_limit)?;
            let processes = inventory_running_processes(platform.clone(), &self.runner, 100)?;
            let process_findings = assess_processes(&processes);
            let app_findings = if let Some(nvd) = &self.nvd_client {
                Self::map_applications_to_cves(nvd, &apps)?
            } else {
                vec![]
            };
            (app_findings, apps, processes, process_findings)
        } else {
            (vec![], vec![], vec![], vec![])
        };

        // Collect system logs
        let system_logs = if collect_logs {
            collect_system_logs(platform.clone(), &self.runner, log_hours)?
        } else {
            vec![]
        };

        // Scan Active Directory
        let ad_findings = if scan_ad {
            scan_active_directory(&self.runner)?
        } else {
            vec![]
        };

        // Generate remediation script
        let failed_results: Vec<CheckResult> = results.iter()
            .filter_map(|(_, r)| if r.status == CheckStatus::Fail { Some(r.clone()) } else { None })
            .collect();

        let remediation_path = if generate_remediation && !failed_results.is_empty() {
            Some(write_remediation_script(output_dir, &platform, &failed_results)?
                .to_string_lossy()
                .to_string())
        } else {
            None
        };

        // Export report bundle
        let summary = crate::reporting::summarize_results(&results);
        let report = AuditReport {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            target_platform: platform.clone(),
            os_info: os_info.clone(),
            results: results.clone(),
            summary,
            application_findings,
            scanned_applications,
            scanned_processes,
            process_findings,
            system_logs,
            ad_findings,
            remediation_path: remediation_path.clone(),
        };

        // Export report bundle
        let _ = export_report_bundle(&report, output_dir, save_to_desktop)?;

        Ok(report)
    }

    fn map_applications_to_cves(
        nvd: &NvdClient,
        applications: &[InstalledApplication],
    ) -> Result<Vec<ApplicationFinding>> {
        let mut findings = vec![];

        for app in applications {
            let cpes = nvd.search_cpes(&app.name, 3)?;
            let mut cves = vec![];
            let mut cpe_name = None;

            for cpe in cpes {
                cpe_name = Some(cpe.cpe_name.clone());
                let app_cves = nvd.fetch_cves_by_cpe(&cpe.cpe_name, 5)?;
                cves.extend(app_cves);
                break; // Use first CPE match
            }

            findings.push(ApplicationFinding {
                application: app.clone(),
                cpe_name,
                cves,
            });
        }

        Ok(findings)
    }
}