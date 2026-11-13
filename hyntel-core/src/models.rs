use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use crate::command_runner::CommandRunner;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

impl Platform {
    pub fn detect() -> Self {
        match std::env::consts::OS {
            "linux" => Platform::Linux,
            "macos" => Platform::MacOS,
            "windows" => Platform::Windows,
            _ => Platform::Unknown,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "linux" => Some(Platform::Linux),
            "macos" | "darwin" => Some(Platform::MacOS),
            "windows" => Some(Platform::Windows),
            "auto" => Some(Platform::detect()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveQuery {
    pub keyword: String,
    pub product_hint: Option<String>,
}

pub type CheckFn = fn(&CommandRunner) -> std::result::Result<CheckResult, anyhow::Error>;

#[derive(Debug, Clone)]
pub struct AuditRule {
    pub id: String,
    pub platform: Platform,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub severity: Severity,
    pub remediation: Vec<String>,
    pub cve_queries: Vec<CveQuery>,
    pub standards: Vec<String>,
    pub check: CheckFn,
}

// Manual serde for AuditRule since it contains a function pointer
impl Serialize for AuditRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AuditRule", 10)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("platform", &self.platform)?;
        state.serialize_field("title", &self.title)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("rationale", &self.rationale)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("remediation", &self.remediation)?;
        state.serialize_field("cve_queries", &self.cve_queries)?;
        state.serialize_field("standards", &self.standards)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AuditRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AuditRuleData {
            id: String,
            platform: Platform,
            title: String,
            description: String,
            rationale: String,
            severity: Severity,
            remediation: Vec<String>,
            cve_queries: Vec<CveQuery>,
            standards: Vec<String>,
        }

        let data = AuditRuleData::deserialize(deserializer)?;
        // Note: check function cannot be deserialized, will be set by get_rules()
        Ok(AuditRule {
            id: data.id,
            platform: data.platform,
            title: data.title,
            description: data.description,
            rationale: data.rationale,
            severity: data.severity,
            remediation: data.remediation,
            cve_queries: data.cve_queries,
            standards: data.standards,
            check: |_| Ok(CheckResult {
                rule_id: String::new(),
                status: CheckStatus::Skip,
                details: "Deserialized rule - check function not available".to_string(),
                observed_value: None,
                remediation: vec![],
                related_cves: vec![],
            }),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub rule_id: String,
    pub status: CheckStatus,
    pub details: String,
    pub observed_value: Option<String>,
    pub remediation: Vec<String>,
    pub related_cves: Vec<CveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub id: Option<String>,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    pub severity: Option<String>,
    pub score: Option<f32>,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApplication {
    pub name: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationFinding {
    pub application: InstalledApplication,
    pub cpe_name: Option<String>,
    pub cves: Vec<CveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub build: Option<String>,
    pub kernel: Option<String>,
    pub security_patches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub name: String,
    pub provider: String,
    pub signer: Option<String>,
    pub sign_type: String,
    pub is_signed: bool,
    pub is_suspicious: bool,
    pub is_dangerous: bool,
    pub inf_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFinding {
    pub process: RunningProcess,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub recommended_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub target_platform: Platform,
    pub os_info: OsInfo,
    pub results: Vec<(AuditRule, CheckResult)>,
    pub summary: AuditSummary,
    pub application_findings: Vec<ApplicationFinding>,
    pub scanned_applications: Vec<InstalledApplication>,
    pub scanned_processes: Vec<RunningProcess>,
    pub process_findings: Vec<ProcessFinding>,
    pub system_logs: Vec<LogEntry>,
    pub ad_findings: Vec<AdFinding>,
    pub remediation_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl AuditSummary {
    pub fn from_results(results: &[(AuditRule, CheckResult)]) -> Self {
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;
        for (_, result) in results {
            match result.status {
                CheckStatus::Pass => passed += 1,
                CheckStatus::Fail => failed += 1,
                CheckStatus::Skip => skipped += 1,
            }
        }
        Self { passed, failed, skipped }
    }
}

impl Default for AuditSummary {
    fn default() -> Self {
        Self { passed: 0, failed: 0, skipped: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStandard {
    pub name: String,
    pub rules: Vec<String>,
}

impl Default for ComplianceStandard {
    fn default() -> Self {
        Self { name: "general".to_string(), rules: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub level: String,
    pub message: String,
    pub unit: Option<String>,
    pub pid: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdFinding {
    pub finding_type: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub target: String,
    pub details: String,
    pub remediation: Vec<String>,
}