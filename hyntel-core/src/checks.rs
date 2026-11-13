use anyhow::Result;
use crate::models::{AuditRule, CheckResult, CheckStatus, CveQuery, Platform, Severity, CommandResult};
use crate::command_runner::CommandRunner;

type CheckFn = fn(&CommandRunner) -> Result<CheckResult>;

pub fn get_rules(platform: Platform) -> Vec<AuditRule> {
    match platform {
        Platform::Linux => linux_rules(),
        Platform::MacOS => macos_rules(),
        Platform::Windows => windows_rules(),
        Platform::Unknown => vec![],
    }
}

fn linux_rules() -> Vec<AuditRule> {
    vec![
        AuditRule {
            id: "linux_firewall_enabled".to_string(),
            platform: Platform::Linux,
            title: "Linux firewall enabled".to_string(),
            description: "Verify a supported firewall service is active.".to_string(),
            rationale: "A host-based firewall reduces the network attack surface.".to_string(),
            severity: Severity::High,
            check: check_linux_firewall,
            remediation: vec![
                "sudo ufw enable".to_string(),
                "sudo systemctl enable --now firewalld".to_string(),
                "sudo systemctl enable --now nftables".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Linux firewall bypass vulnerability".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "linux_sshd_root_login_disabled".to_string(),
            platform: Platform::Linux,
            title: "SSH root login disabled".to_string(),
            description: "Verify SSH root login is disabled.".to_string(),
            rationale: "Direct root login over SSH increases risk of credential compromise.".to_string(),
            severity: Severity::Critical,
            check: check_linux_sshd_root_login,
            remediation: vec![
                "echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config".to_string(),
                "sudo systemctl reload sshd".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "OpenSSH root login privilege escalation".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "linux_sshd_password_auth_disabled".to_string(),
            platform: Platform::Linux,
            title: "SSH password authentication disabled".to_string(),
            description: "Verify SSH password authentication is disabled.".to_string(),
            rationale: "Key-based authentication is more resistant to brute-force attacks.".to_string(),
            severity: Severity::High,
            check: check_linux_sshd_password_auth,
            remediation: vec![
                "echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config".to_string(),
                "sudo systemctl reload sshd".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "OpenSSH password authentication brute force".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "linux_auto_updates_enabled".to_string(),
            platform: Platform::Linux,
            title: "Automatic security updates enabled".to_string(),
            description: "Verify automatic security updates are configured.".to_string(),
            rationale: "Timely patching reduces exposure to known vulnerabilities.".to_string(),
            severity: Severity::High,
            check: check_linux_auto_updates,
            remediation: vec![
                "sudo apt-get install -y unattended-upgrades".to_string(),
                "sudo systemctl enable --now unattended-upgrades".to_string(),
                "sudo dnf install -y dnf-automatic".to_string(),
                "sudo systemctl enable --now dnf-automatic.timer".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Linux unpatched vulnerability exploitation".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
    ]
}

fn macos_rules() -> Vec<AuditRule> {
    vec![
        AuditRule {
            id: "macos_firewall_enabled".to_string(),
            platform: Platform::MacOS,
            title: "macOS application firewall enabled".to_string(),
            description: "Verify the macOS application firewall is enabled.".to_string(),
            rationale: "The application firewall controls incoming connections per application.".to_string(),
            severity: Severity::High,
            check: check_macos_firewall,
            remediation: vec![
                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "macOS firewall bypass network attack".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "macos_filevault_enabled".to_string(),
            platform: Platform::MacOS,
            title: "FileVault disk encryption enabled".to_string(),
            description: "Verify FileVault full-disk encryption is enabled.".to_string(),
            rationale: "Full-disk encryption protects data at rest against physical access.".to_string(),
            severity: Severity::Critical,
            check: check_macos_filevault,
            remediation: vec![
                "sudo fdesetup enable".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "macOS FileVault encryption bypass".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "macos_remote_login_disabled".to_string(),
            platform: Platform::MacOS,
            title: "Remote Login (SSH) disabled".to_string(),
            description: "Verify Remote Login is disabled unless required.".to_string(),
            rationale: "Unneeded remote access services increase attack surface.".to_string(),
            severity: Severity::Critical,
            check: check_macos_remote_login,
            remediation: vec![
                "sudo systemsetup -setremotelogin off".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "macOS SSH remote code execution".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "macos_auto_updates_enabled".to_string(),
            platform: Platform::MacOS,
            title: "Automatic updates enabled".to_string(),
            description: "Verify automatic macOS updates are enabled.".to_string(),
            rationale: "Automatic updates ensure timely security patches.".to_string(),
            severity: Severity::High,
            check: check_macos_auto_updates,
            remediation: vec![
                "sudo softwareupdate --schedule on".to_string(),
                "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "macOS unpatched vulnerability exploitation".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
    ]
}

fn windows_rules() -> Vec<AuditRule> {
    vec![
        AuditRule {
            id: "windows_firewall_profiles_enabled".to_string(),
            platform: Platform::Windows,
            title: "Windows Firewall profiles enabled".to_string(),
            description: "Verify Windows Firewall is enabled for all profiles.".to_string(),
            rationale: "Active firewall profiles protect against unauthorized network access.".to_string(),
            severity: Severity::High,
            check: check_windows_firewall,
            remediation: vec![
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Windows Firewall bypass network intrusion".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "windows_bitlocker_enabled".to_string(),
            platform: Platform::Windows,
            title: "BitLocker drive encryption enabled".to_string(),
            description: "Verify BitLocker protection is enabled on OS drive.".to_string(),
            rationale: "Disk encryption protects offline data disclosure scenarios.".to_string(),
            severity: Severity::High,
            check: check_windows_bitlocker,
            remediation: vec![
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Windows BitLocker encryption bypass".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "windows_rdp_disabled".to_string(),
            platform: Platform::Windows,
            title: "Remote Desktop disabled".to_string(),
            description: "Verify Remote Desktop is disabled unless explicitly required.".to_string(),
            rationale: "Unneeded remote administration services increase attack surface.".to_string(),
            severity: Severity::Critical,
            check: check_windows_rdp,
            remediation: vec![
                "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Windows Remote Desktop RDP remote code execution".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "windows_defender_realtime_enabled".to_string(),
            platform: Platform::Windows,
            title: "Windows Defender real-time monitoring enabled".to_string(),
            description: "Verify Microsoft Defender real-time monitoring is enabled.".to_string(),
            rationale: "Real-time scanning helps prevent known malware execution paths.".to_string(),
            severity: Severity::High,
            check: check_windows_defender_realtime,
            remediation: vec![
                "Set-MpPreference -DisableRealtimeMonitoring $false".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Microsoft Defender bypass vulnerability malware".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
        AuditRule {
            id: "windows_driver_signing".to_string(),
            platform: Platform::Windows,
            title: "Windows driver signing verification".to_string(),
            description: "Check all installed PnP drivers for valid signatures.".to_string(),
            rationale: "Unsigned or improperly signed drivers can be exploited for kernel-level code execution.".to_string(),
            severity: Severity::Critical,
            check: check_windows_driver_signing,
            remediation: vec![
                "Get-WmiObject Win32_PnPSignedDriver | Where-Object { -not $_.IsSigned } | Select-Object DeviceName, InfName".to_string(),
                "Identify and remove or update any unsigned drivers.".to_string(),
                "bcdedit /set nointegritychecks off".to_string(),
            ],
            cve_queries: vec![
                CveQuery { keyword: "Windows unsigned driver privilege escalation kernel exploit".to_string(), product_hint: None },
            ],
            standards: vec!["ISO27001".to_string(), "HIPAA".to_string(), "PCI_DSS".to_string()],
        },
    ]
}

fn check_linux_firewall(runner: &CommandRunner) -> Result<CheckResult> {
    if runner.exists("ufw") {
        let result = runner.run(&["ufw", "status"])?;
        let output = format!("{} {}", result.stdout, result.stderr).to_lowercase();
        if output.contains("status: active") {
            return Ok(pass("linux_firewall_enabled", "UFW is active.", Some(result.stdout)));
        }
        return Ok(fail("linux_firewall_enabled", "UFW is installed but inactive.", Some(result.stdout)));
    }

    if runner.exists("systemctl") {
        for service in ["firewalld", "nftables"] {
            let result = runner.run(&["systemctl", "is-active", service])?;
            if result.returncode == 0 && result.stdout.trim() == "active" {
                return Ok(pass("linux_firewall_enabled", &format!("{} is active.", service), Some(service.to_string())));
            }
        }
        return Ok(fail("linux_firewall_enabled", "No supported active firewall service detected.", Some("firewalld/nftables inactive".to_string())));
    }

    Ok(skip("linux_firewall_enabled", "No supported firewall tool found on host."))
}

fn check_linux_sshd_root_login(runner: &CommandRunner) -> Result<CheckResult> {
    let value = read_sshd_config(runner, "PermitRootLogin")?;
    match value.as_deref() {
        Some(v) if v.eq_ignore_ascii_case("no") || v.eq_ignore_ascii_case("prohibit-password") => {
            Ok(pass("linux_sshd_root_login_disabled", "Root SSH login is disabled.", value))
        }
        Some(v) => Ok(fail("linux_sshd_root_login_disabled", "Root SSH login is allowed.", Some(v.to_string()))),
        None => Ok(skip("linux_sshd_root_login_disabled", "Could not determine PermitRootLogin from sshd_config.")),
    }
}

fn check_linux_sshd_password_auth(runner: &CommandRunner) -> Result<CheckResult> {
    let value = read_sshd_config(runner, "PasswordAuthentication")?;
    match value.as_deref() {
        Some(v) if v.eq_ignore_ascii_case("no") => {
            Ok(pass("linux_sshd_password_auth_disabled", "SSH password authentication is disabled.", value))
        }
        Some(v) => Ok(fail("linux_sshd_password_auth_disabled", "SSH password authentication is enabled.", Some(v.to_string()))),
        None => Ok(skip("linux_sshd_password_auth_disabled", "Could not determine PasswordAuthentication from sshd_config.")),
    }
}

fn read_sshd_config(runner: &CommandRunner, key: &str) -> Result<Option<String>> {
    let config_path = "/etc/ssh/sshd_config";
    let cmd = format!("test -f {} && sed -n 's/^\\s*{} \\+//Ip' {} | tail -n 1", config_path, key, config_path);
    let result = runner.run_shell(&cmd)?;
    if result.returncode != 0 || result.stdout.is_empty() {
        return Ok(None);
    }
    Ok(Some(result.stdout.trim().to_string()))
}

fn check_linux_auto_updates(runner: &CommandRunner) -> Result<CheckResult> {
    if runner.exists("systemctl") {
        for service in ["apt-daily-upgrade.timer", "dnf-automatic.timer", "unattended-upgrades.service"] {
            let result = runner.run(&["systemctl", "is-enabled", service])?;
            if result.returncode == 0 && (result.stdout.trim() == "enabled" || result.stdout.trim() == "static") {
                return Ok(pass("linux_auto_updates_enabled", &format!("{} is enabled.", service), Some(result.stdout)));
            }
        }
    }
    Ok(fail("linux_auto_updates_enabled", "No supported automatic update service is enabled.", None))
}

fn check_macos_firewall(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run(&["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])?;
    let output = format!("{} {}", result.stdout, result.stderr).to_lowercase();
    if output.contains("enabled") {
        return Ok(pass("macos_firewall_enabled", "macOS application firewall is enabled.", Some(result.stdout)));
    }
    if result.returncode == 127 {
        return Ok(skip("macos_firewall_enabled", "socketfilterfw is not available."));
    }
    Ok(fail("macos_firewall_enabled", "macOS application firewall is disabled.", Some(result.stdout)))
}

fn check_macos_filevault(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run(&["fdesetup", "status"])?;
    let output = format!("{} {}", result.stdout, result.stderr).to_lowercase();
    if output.contains("filevault is on") {
        return Ok(pass("macos_filevault_enabled", "FileVault is enabled.", Some(result.stdout)));
    }
    if result.returncode == 127 {
        return Ok(skip("macos_filevault_enabled", "fdesetup is not available."));
    }
    if output.contains("unknown volume") || output.contains("not supported") {
        return Ok(skip("macos_filevault_enabled", "FileVault status unavailable in current environment."));
    }
    Ok(fail("macos_filevault_enabled", "FileVault is not enabled.", Some(result.stdout)))
}

fn check_macos_remote_login(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run(&["systemsetup", "-getremotelogin"])?;
    let output = format!("{} {}", result.stdout, result.stderr).to_lowercase();
    if output.contains("off") {
        return Ok(pass("macos_remote_login_disabled", "Remote Login is disabled.", Some(result.stdout)));
    }
    if output.contains("requires admin") || output.contains("administrator access") {
        return Ok(skip("macos_remote_login_disabled", "Remote Login status requires elevated privileges."));
    }
    Ok(fail("macos_remote_login_disabled", "Remote Login is enabled.", Some(result.stdout)))
}

fn check_macos_auto_updates(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run(&["softwareupdate", "--schedule"])?;
    let output = format!("{} {}", result.stdout, result.stderr).to_lowercase();
    if output.contains("on") {
        return Ok(pass("macos_auto_updates_enabled", "Automatic updates are enabled.", Some(result.stdout)));
    }
    Ok(fail("macos_auto_updates_enabled", "Automatic updates are not enabled.", None))
}

fn check_windows_firewall(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run_shell(
        r#"Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"#,
    )?;
    if result.returncode != 0 || result.stdout.is_empty() {
        return Ok(fail("windows_firewall_profiles_enabled", "Could not query firewall profiles.", None));
    }

    let profiles_json: serde_json::Value = serde_json::from_str(&result.stdout)?;
    let empty_vec = vec![];
    let profiles = profiles_json.as_array().unwrap_or(&empty_vec);
    let mut all_enabled = true;
    let mut details = vec![];

    for profile in profiles {
        let name = profile.get("Name").and_then(|v| v.as_str()).unwrap_or("unknown");
        let enabled = profile.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        details.push(format!("{}: {}", name, if enabled { "enabled" } else { "disabled" }));
        if !enabled {
            all_enabled = false;
        }
    }

    if all_enabled {
        Ok(pass("windows_firewall_profiles_enabled", "All firewall profiles are enabled.", Some(details.join(", "))))
    } else {
        Ok(fail("windows_firewall_profiles_enabled", "Some firewall profiles are disabled.", Some(details.join(", "))))
    }
}

fn check_windows_bitlocker(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run_shell(
        r#"Get-BitLockerVolume -MountPoint 'C:' | Select-Object VolumeStatus, EncryptionMethod | ConvertTo-Json -Compress"#,
    )?;
    if result.returncode != 0 {
        return Ok(skip("windows_bitlocker_enabled", "Could not query BitLocker status."));
    }

    let volume: serde_json::Value = serde_json::from_str(&result.stdout)?;
    let status = volume.get("VolumeStatus").and_then(|v| v.as_str()).unwrap_or("");
    let method = volume.get("EncryptionMethod").and_then(|v| v.as_str()).unwrap_or("");

    if status.eq_ignore_ascii_case("fullyencrypted") || status.eq_ignore_ascii_case("encryptioninprogress") {
        Ok(pass("windows_bitlocker_enabled", &format!("BitLocker is {} ({}).", status, method), Some(result.stdout)))
    } else {
        Ok(fail("windows_bitlocker_enabled", &format!("BitLocker is not enabled (status: {}).", status), Some(result.stdout)))
    }
}

fn check_windows_rdp(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run_shell(
        r#"Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' | Select-Object -ExpandProperty fDenyTSConnections"#,
    )?;
    let value = result.stdout.trim();
    if value == "1" {
        Ok(pass("windows_rdp_disabled", "Remote Desktop is disabled.", Some("fDenyTSConnections=1".to_string())))
    } else {
        Ok(fail("windows_rdp_disabled", "Remote Desktop is enabled.", Some("fDenyTSConnections=0".to_string())))
    }
}

fn check_windows_defender_realtime(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run_shell(
        r#"Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring"#,
    )?;
    let value = result.stdout.trim();
    if value.eq_ignore_ascii_case("false") {
        Ok(pass("windows_defender_realtime_enabled", "Real-time monitoring is enabled.", Some("DisableRealtimeMonitoring=False".to_string())))
    } else {
        Ok(fail("windows_defender_realtime_enabled", "Real-time monitoring is disabled.", Some("DisableRealtimeMonitoring=True".to_string())))
    }
}

fn check_windows_driver_signing(runner: &CommandRunner) -> Result<CheckResult> {
    let result = runner.run_shell(
        r#"Get-WmiObject Win32_PnPSignedDriver | Where-Object { -not $_.IsSigned } | Select-Object DeviceName, InfName | ConvertTo-Json -Compress"#,
    )?;
    if result.returncode != 0 {
        return Ok(skip("windows_driver_signing", "Could not query driver signatures."));
    }

    let drivers_json: serde_json::Value = serde_json::from_str(&result.stdout)?;
    let empty_vec = vec![];
    let drivers = drivers_json.as_array().unwrap_or(&empty_vec);

    if drivers.is_empty() {
        Ok(pass("windows_driver_signing", "All drivers are properly signed.", Some("0 unsigned drivers".to_string())))
    } else {
        let count = drivers.len();
        let details = drivers.iter()
            .filter_map(|d| {
                let name = d.get("DeviceName").and_then(|v| v.as_str())?;
                let inf = d.get("InfName").and_then(|v| v.as_str())?;
                Some(format!("{} ({})", name, inf))
            })
            .collect::<Vec<_>>()
            .join("; ");
        Ok(fail("windows_driver_signing", &format!("{} unsigned driver(s) found.", count), Some(details)))
    }
}

fn pass(rule_id: &str, details: &str, observed: Option<String>) -> CheckResult {
    CheckResult {
        rule_id: rule_id.to_string(),
        status: CheckStatus::Pass,
        details: details.to_string(),
        observed_value: observed,
        remediation: vec![],
        related_cves: vec![],
    }
}

fn fail(rule_id: &str, details: &str, observed: Option<String>) -> CheckResult {
    CheckResult {
        rule_id: rule_id.to_string(),
        status: CheckStatus::Fail,
        details: details.to_string(),
        observed_value: observed,
        remediation: vec![],
        related_cves: vec![],
    }
}

fn skip(rule_id: &str, details: &str) -> CheckResult {
    CheckResult {
        rule_id: rule_id.to_string(),
        status: CheckStatus::Skip,
        details: details.to_string(),
        observed_value: None,
        remediation: vec![],
        related_cves: vec![],
    }
}