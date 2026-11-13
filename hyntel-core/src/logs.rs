use anyhow::Result;
use crate::models::{LogEntry, Platform};
use crate::command_runner::CommandRunner;
use chrono::{DateTime, Utc};

pub fn collect_system_logs(platform: Platform, runner: &CommandRunner, since_hours: i64) -> Result<Vec<LogEntry>> {
    match platform {
        Platform::Linux => collect_linux_logs(runner, since_hours),
        Platform::MacOS => collect_macos_logs(runner, since_hours),
        Platform::Windows => collect_windows_logs(runner, since_hours),
        Platform::Unknown => Ok(vec![]),
    }
}

fn collect_linux_logs(runner: &CommandRunner, since_hours: i64) -> Result<Vec<LogEntry>> {
    let mut entries = vec![];

    // journalctl for systemd logs
    let since = format!("{} hours ago", since_hours);
    let result = runner.run(&["journalctl", "--since", &since, "-o", "json", "--no-pager"])?;
    if result.returncode == 0 {
        for line in result.stdout.lines() {
            if let Some(entry) = parse_journalctl_json(line) {
                entries.push(entry);
            }
        }
    }

    // auth.log for authentication events
    let auth_result = runner.run(&["grep", "-h", ".", "/var/log/auth.log", "/var/log/secure", "2>/dev/null"])?;
    if auth_result.returncode == 0 {
        for line in auth_result.stdout.lines() {
            if let Some(entry) = parse_auth_log_line(line) {
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

fn parse_journalctl_json(line: &str) -> Option<LogEntry> {
    use serde_json::Value;
    let json: Value = serde_json::from_str(line).ok()?;
    
    Some(LogEntry {
        timestamp: json.get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|ms| DateTime::from_timestamp_millis(ms as i64).unwrap_or_else(|| Utc::now()))
            .unwrap_or_else(|| Utc::now()),
        source: "journalctl".to_string(),
        level: json.get("PRIORITY").and_then(|v| v.as_str()).unwrap_or("info").to_string(),
        message: json.get("MESSAGE").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        unit: json.get("_SYSTEMD_UNIT").and_then(|v| v.as_str()).map(|s| s.to_string()),
        pid: json.get("_PID").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()),
        user: json.get("_UID").and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}

fn parse_auth_log_line(line: &str) -> Option<LogEntry> {
    // Basic auth.log parsing: "Mar 15 10:30:45 hostname sshd[1234]: message"
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return None;
    }
    
    Some(LogEntry {
        timestamp: Utc::now(), // Would need proper parsing
        source: "auth.log".to_string(),
        level: "info".to_string(),
        message: parts[3].to_string(),
        unit: Some(parts[2].to_string()),
        pid: None,
        user: None,
    })
}

fn collect_macos_logs(runner: &CommandRunner, since_hours: i64) -> Result<Vec<LogEntry>> {
    let mut entries = vec![];

    // log show for unified logging
    let since = format!("-{}h", since_hours);
    let result = runner.run(&["log", "show", "--style", "json", "--predicate", "eventType == logEvent", "--last", &since])?;
    if result.returncode == 0 {
        for line in result.stdout.lines() {
            if let Some(entry) = parse_macos_log_json(line) {
                entries.push(entry);
            }
        }
    }

    // Also check /var/log/system.log
    let syslog_result = runner.run(&["tail", "-n", "1000", "/var/log/system.log"])?;
    if syslog_result.returncode == 0 {
        for line in syslog_result.stdout.lines() {
            if let Some(entry) = parse_syslog_line(line) {
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

fn parse_macos_log_json(line: &str) -> Option<LogEntry> {
    use serde_json::Value;
    let json: Value = serde_json::from_str(line).ok()?;
    
    Some(LogEntry {
        timestamp: json.get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now()),
        source: "macos_log".to_string(),
        level: json.get("level").and_then(|v| v.as_str()).unwrap_or("info").to_string(),
        message: json.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        unit: json.get("subsystem").and_then(|v| v.as_str()).map(|s| s.to_string()),
        pid: json.get("processID").and_then(|v| v.as_u64()).map(|n| n as u32),
        user: None,
    })
}

fn parse_syslog_line(line: &str) -> Option<LogEntry> {
    // Basic syslog parsing
    Some(LogEntry {
        timestamp: Utc::now(),
        source: "system.log".to_string(),
        level: "info".to_string(),
        message: line.to_string(),
        unit: None,
        pid: None,
        user: None,
    })
}

fn collect_windows_logs(runner: &CommandRunner, since_hours: i64) -> Result<Vec<LogEntry>> {
    let mut entries = vec![];

    // Security log (requires admin)
    let security_cmd = format!(
        "Get-WinEvent -LogName Security -MaxEvents 500 | Where-Object {{ $_.TimeCreated -ge (Get-Date).AddHours(-{}) }} | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Compress",
        since_hours
    );
    let result = runner.run_shell(&security_cmd)?;
    if result.returncode == 0 && !result.stdout.is_empty() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result.stdout) {
            if let Some(arr) = json.as_array() {
                for item in arr {
                    if let Some(entry) = parse_windows_event(item) {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    // System log
    let system_cmd = format!(
        "Get-WinEvent -LogName System -MaxEvents 500 | Where-Object {{ $_.TimeCreated -ge (Get-Date).AddHours(-{}) }} | Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName | ConvertTo-Json -Compress",
        since_hours
    );
    let result = runner.run_shell(&system_cmd)?;
    if result.returncode == 0 && !result.stdout.is_empty() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result.stdout) {
            if let Some(arr) = json.as_array() {
                for item in arr {
                    if let Some(entry) = parse_windows_event(item) {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    Ok(entries)
}

fn parse_windows_event(json: &serde_json::Value) -> Option<LogEntry> {
    Some(LogEntry {
        timestamp: json.get("TimeCreated").and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now()),
        source: "windows_event".to_string(),
        level: json.get("LevelDisplayName").and_then(|v| v.as_str()).unwrap_or("info").to_string(),
        message: json.get("Message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        unit: json.get("ProviderName").and_then(|v| v.as_str()).map(|s| s.to_string()),
        pid: None,
        user: None,
    })
}

pub fn filter_security_events(entries: &[LogEntry]) -> Vec<LogEntry> {
    let security_keywords = [
        "login", "logon", "authentication", "failed", "success", "ssh", "rdp", "rdp",
        "device", "usb", "mount", "unmount", "network", "share", "smb", "cifs",
        "sudo", "su ", "passwd", "shadow", "pam", "gssapi", "kerberos",
    ];
    
    entries.iter()
        .filter(|e| {
            let msg = e.message.to_lowercase();
            security_keywords.iter().any(|k| msg.contains(k))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_security_events() {
        let entries = vec![
            LogEntry { timestamp: Utc::now(), source: "test".into(), level: "info".into(), message: "User login successful".into(), unit: None, pid: None, user: None },
            LogEntry { timestamp: Utc::now(), source: "test".into(), level: "error".into(), message: "Failed password for user".into(), unit: None, pid: None, user: None },
            LogEntry { timestamp: Utc::now(), source: "test".into(), level: "info".into(), message: "USB device connected".into(), unit: None, pid: None, user: None },
            LogEntry { timestamp: Utc::now(), source: "test".into(), level: "info".into(), message: "System startup complete".into(), unit: None, pid: None, user: None },
        ];
        
        let filtered = filter_security_events(&entries);
        assert_eq!(filtered.len(), 3); // login, failed, usb
    }
}