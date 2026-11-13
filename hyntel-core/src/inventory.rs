use anyhow::Result;
use crate::models::{InstalledApplication, RunningProcess, Platform, ProcessFinding, Severity};
use crate::command_runner::CommandRunner;

pub fn inventory_applications(platform: Platform, runner: &CommandRunner, limit: usize) -> Result<Vec<InstalledApplication>> {
    match platform {
        Platform::Linux => inventory_linux(runner, limit),
        Platform::MacOS => inventory_macos(runner, limit),
        Platform::Windows => inventory_windows(runner, limit),
        Platform::Unknown => Ok(vec![]),
    }
}

fn inventory_linux(runner: &CommandRunner, limit: usize) -> Result<Vec<InstalledApplication>> {
    if runner.exists("dpkg-query") {
        let result = runner.run(&["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])?;
        if result.returncode == 0 {
            let mut apps = vec![];
            for line in result.stdout.lines() {
                if line.trim().is_empty() || !line.contains('\t') {
                    continue;
                }
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() == 2 {
                    apps.push(InstalledApplication {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        source: "dpkg".to_string(),
                    });
                }
            }
            return Ok(apps.into_iter().take(limit).collect());
        }
    }

    if runner.exists("rpm") {
        let result = runner.run(&["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])?;
        if result.returncode == 0 {
            let mut apps = vec![];
            for line in result.stdout.lines() {
                if line.trim().is_empty() || !line.contains('\t') {
                    continue;
                }
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() == 2 {
                    apps.push(InstalledApplication {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        source: "rpm".to_string(),
                    });
                }
            }
            return Ok(apps.into_iter().take(limit).collect());
        }
    }

    if runner.exists("pacman") {
        let result = runner.run(&["pacman", "-Q"])?;
        if result.returncode == 0 {
            let mut apps = vec![];
            for line in result.stdout.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    apps.push(InstalledApplication {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        source: "pacman".to_string(),
                    });
                }
            }
            return Ok(apps.into_iter().take(limit).collect());
        }
    }

    Ok(vec![])
}

fn inventory_macos(runner: &CommandRunner, limit: usize) -> Result<Vec<InstalledApplication>> {
    let mut apps = vec![];

    if runner.exists("brew") {
        let result = runner.run(&["brew", "list", "--versions"])?;
        if result.returncode == 0 {
            for line in result.stdout.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    apps.push(InstalledApplication {
                        name: parts[0].to_string(),
                        version: parts[1..].join(" "),
                        source: "brew".to_string(),
                    });
                }
            }
        }
    }

    // Also check /Applications
    if let Ok(entries) = std::fs::read_dir("/Applications") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".app") {
                    let app_name = name.trim_end_matches(".app");
                    let plist_path = entry.path().join("Contents/Info.plist");
                    let version = if plist_path.exists() {
                        read_plist_version(&plist_path).unwrap_or_else(|| "unknown".to_string())
                    } else {
                        "unknown".to_string()
                    };
                    apps.push(InstalledApplication {
                        name: app_name.to_string(),
                        version,
                        source: "applications".to_string(),
                    });
                }
            }
        }
    }

    Ok(apps.into_iter().take(limit).collect())
}

fn read_plist_version(plist_path: &std::path::Path) -> Option<String> {
    use std::process::Command;
    let output = Command::new("plutil")
        .args(["-extract", "CFBundleShortVersionString", "xml1", "-o", "-", plist_path.to_str()?])
        .output()
        .ok()?;
    if output.status.success() {
        let xml = String::from_utf8_lossy(&output.stdout);
        if let Some(start) = xml.find("<string>") {
            let start = start + 8;
            if let Some(end) = xml[start..].find("</string>") {
                return Some(xml[start..start+end].to_string());
            }
        }
    }
    None
}

fn inventory_windows(runner: &CommandRunner, limit: usize) -> Result<Vec<InstalledApplication>> {
    let result = runner.run_shell(
        r#"Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json -Compress"#,
    )?;

    if result.returncode != 0 || result.stdout.is_empty() {
        return Ok(vec![]);
    }

    let apps_json: serde_json::Value = serde_json::from_str(&result.stdout)?;
    let empty_vec = vec![];
    let apps = apps_json.as_array().unwrap_or(&empty_vec);

    let mut results = vec![];
    for app in apps {
        let name = app.get("DisplayName").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let version = app.get("DisplayVersion").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let publisher = app.get("Publisher").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        if !name.is_empty() {
            results.push(InstalledApplication {
                name,
                version,
                source: format!("registry:{}", publisher),
            });
        }
    }

    Ok(results.into_iter().take(limit).collect())
}

pub fn inventory_running_processes(_platform: Platform, _runner: &CommandRunner, limit: usize) -> Result<Vec<RunningProcess>> {
    let sys = sysinfo::System::new_all();
    let mut processes = vec![];

    for (pid, process) in sys.processes() {
        if processes.len() >= limit {
            break;
        }
        processes.push(RunningProcess {
            pid: pid.as_u32(),
            name: process.name().to_string(),
            executable: process.exe().map(|p| p.to_string_lossy().to_string()),
            command_line: Some(process.cmd().join(" ")),
            source: "sysinfo".to_string(),
        });
    }

    // Sort by PID for consistent output
    processes.sort_by_key(|p| p.pid);
    Ok(processes)
}

pub fn assess_processes(processes: &[RunningProcess]) -> Vec<ProcessFinding> {
    let mut findings = vec![];

    for process in processes {
        let mut reasons = vec![];
        let mut severity = Severity::Low;

        // Check for suspicious characteristics
        if let Some(exe) = &process.executable {
            let exe_lower = exe.to_lowercase();
            // Running from temp directories
            if exe_lower.contains("/tmp/") || exe_lower.contains("\\temp\\") || exe_lower.contains("\\appdata\\local\\temp\\") {
                reasons.push("Executable running from temporary directory".to_string());
                severity = Severity::Medium;
            }
            // Unusual locations
            if exe_lower.contains("/dev/shm/") || exe_lower.contains("\\windows\\temp\\") {
                reasons.push("Executable running from shared memory/temp directory".to_string());
                severity = Severity::High;
            }
        }

        // Check for suspicious process names
        let name_lower = process.name.to_lowercase();
        let suspicious_names = [
            "nc", "netcat", "ncat", "socat", "cryptcat", "mimikatz", "procdump",
            "psexec", "wmiexec", "smbexec", "atexec", "dcomexec",
        ];
        for suspicious in suspicious_names {
            if name_lower.contains(suspicious) {
                reasons.push(format!("Suspicious process name: {}", suspicious));
                severity = Severity::Critical;
            }
        }

        // Check for processes without executable path (potentially injected)
        if process.executable.is_none() || process.executable.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            reasons.push("Process has no executable path (possible injection/hollowing)".to_string());
            severity = Severity::High;
        }

        if !reasons.is_empty() {
            findings.push(ProcessFinding {
                process: process.clone(),
                severity,
                reasons,
                recommended_action: Some("Investigate process origin and legitimacy".to_string()),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::CommandRunner;

    #[test]
    fn test_inventory_linux_dpkg() {
        let runner = CommandRunner::new();
        if runner.exists("dpkg-query") {
            let apps = inventory_linux(&runner, 10).unwrap();
            assert!(!apps.is_empty());
        }
    }
}