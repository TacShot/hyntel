use anyhow::Result;
use crate::models::{AdFinding, Platform, Severity};
use crate::command_runner::CommandRunner;

pub fn scan_active_directory(runner: &CommandRunner) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    // Only relevant on Windows or Linux with AD integration
    let platform = Platform::detect();
    match platform {
        Platform::Windows => findings.extend(scan_windows_ad(runner)?),
        Platform::Linux => findings.extend(scan_linux_ad(runner)?),
        Platform::MacOS => findings.extend(scan_macos_ad(runner)?),
        Platform::Unknown => {}
    }

    Ok(findings)
}

fn scan_windows_ad(runner: &CommandRunner) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    // Check if domain joined
    let domain_result = runner.run_shell(
        r#"(Get-CimInstance Win32_ComputerSystem).PartOfDomain"#,
    )?;
    let is_domain_joined = domain_result.stdout.trim().eq_ignore_ascii_case("true");

    if is_domain_joined {
        // Get domain info
        let domain_info = runner.run_shell(
            r#"(Get-CimInstance Win32_ComputerSystem).Domain"#,
        )?;
        let domain = domain_info.stdout.trim();

        // Check for insecure LDAP signing
        let ldap_signing = runner.run_shell(
            r#"Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapServerIntegrity' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LdapServerIntegrity"#,
        )?;
        if ldap_signing.stdout.trim() != "1" && ldap_signing.stdout.trim() != "2" {
            findings.push(AdFinding {
                finding_type: "LDAP Signing".to_string(),
                severity: Severity::High,
                title: "LDAP Signing Not Enforced".to_string(),
                description: "Domain controller does not require LDAP signing, allowing potential MITM attacks".to_string(),
                target: format!("Domain: {}", domain),
                details: "LdapServerIntegrity registry value not set to 1 (require signing) or 2 (require signing and encryption)".to_string(),
                remediation: vec![
                    "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapServerIntegrity' -Value 2 -Type DWord".to_string(),
                    "Restart the NTDS service".to_string(),
                ],
            });
        }

        // Check for anonymous LDAP access
        let anon_ldap = runner.run_shell(
            r#"Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RestrictAnonymous"#,
        )?;
        if anon_ldap.stdout.trim() != "1" && anon_ldap.stdout.trim() != "2" {
            findings.push(AdFinding {
                finding_type: "Anonymous LDAP".to_string(),
                severity: Severity::Medium,
                title: "Anonymous LDAP Access Allowed".to_string(),
                description: "Anonymous users can query LDAP directory information".to_string(),
                target: format!("Domain: {}", domain),
                details: "RestrictAnonymous registry value not set to restrict anonymous access".to_string(),
                remediation: vec![
                    "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord".to_string(),
                ],
            });
        }

        // Check SMB signing
        let smb_signing = runner.run_shell(
            r#"Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature"#,
        )?;
        if smb_signing.stdout.trim().eq_ignore_ascii_case("false") {
            findings.push(AdFinding {
                finding_type: "SMB Signing".to_string(),
                severity: Severity::High,
                title: "SMB Signing Not Required".to_string(),
                description: "SMB traffic not signed, allowing potential relay attacks".to_string(),
                target: format!("Domain: {}", domain),
                details: "Server SMB signing not enforced".to_string(),
                remediation: vec![
                    "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force".to_string(),
                ],
            });
        }

        // Check for SMBv1
        let smb1 = runner.run_shell(
            r#"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State"#,
        )?;
        if smb1.stdout.trim().eq_ignore_ascii_case("enabled") {
            findings.push(AdFinding {
                finding_type: "SMBv1".to_string(),
                severity: Severity::Critical,
                title: "SMBv1 Protocol Enabled".to_string(),
                description: "SMBv1 is deprecated and vulnerable to exploits like WannaCry/EternalBlue".to_string(),
                target: format!("Domain: {}", domain),
                details: "SMB 1.0/CIFS File Sharing Support feature is enabled".to_string(),
                remediation: vec![
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol".to_string(),
                ],
            });
        }

        // Enumerate network shares
        findings.extend(enumerate_network_shares(runner, domain)?);
        
        // Check for privileged users
        findings.extend(check_privileged_users(runner)?);
    } else {
        findings.push(AdFinding {
            finding_type: "Domain Membership".to_string(),
            severity: Severity::Info,
            title: "Not Domain Joined".to_string(),
            description: "System is not joined to an Active Directory domain".to_string(),
            target: "Local System".to_string(),
            details: "PartOfDomain returned false".to_string(),
            remediation: vec![],
        });
    }

    Ok(findings)
}

fn enumerate_network_shares(runner: &CommandRunner, domain: &str) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    let shares_result = runner.run_shell(
        r#"Get-SmbShare | Where-Object { $_.Name -notlike '*$' } | Select-Object Name, Path, Description | ConvertTo-Json -Compress"#,
    )?;
    
    if shares_result.returncode == 0 && !shares_result.stdout.is_empty() {
        let shares: serde_json::Value = serde_json::from_str(&shares_result.stdout).unwrap_or(serde_json::Value::Array(vec![]));
        let empty_vec = vec![];
        let shares = shares.as_array().unwrap_or(&empty_vec);
        
        for share in shares {
            let name = share.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let path = share.get("Path").and_then(|v| v.as_str()).unwrap_or("");
            
            // Check for everyone/full control
            let perms_result = runner.run_shell(&format!(
                r#"Get-SmbShareAccess -Name "{}" | Where-Object {{ $_.AccessRight -eq 'Full' -and ($_.AccountName -eq 'Everyone' -or $_.AccountName -eq 'BUILTIN\Users') }} | Select-Object AccountName, AccessRight | ConvertTo-Json -Compress"#,
                name
            ))?;
            
            if perms_result.returncode == 0 && !perms_result.stdout.trim().is_empty() && perms_result.stdout.trim() != "[]" {
                findings.push(AdFinding {
                    finding_type: "Network Share Permissions".to_string(),
                    severity: Severity::High,
                    title: format!("Overly Permissive Share: {}", name),
                    description: "Network share grants Full Control to Everyone or Users group".to_string(),
                    target: format!("Domain: {}", domain),
                    details: format!("Share '{}' at path '{}' has excessive permissions", name, path),
                    remediation: vec![
                        format!("Revoke Full Control from Everyone/Users on share '{}'", name),
                        "Apply least-privilege permissions".to_string(),
                    ],
                });
            }
        }
    }

    Ok(findings)
}

fn check_privileged_users(runner: &CommandRunner) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    // Check for users with admin rights
    let admins_result = runner.run_shell(
        r#"Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource | ConvertTo-Json -Compress"#,
    )?;
    
    if admins_result.returncode == 0 && !admins_result.stdout.is_empty() {
        let members: serde_json::Value = serde_json::from_str(&admins_result.stdout).unwrap_or(serde_json::Value::Array(vec![]));
        let empty_vec = vec![];
        let members = members.as_array().unwrap_or(&empty_vec);
        
        for member in members {
            let name = member.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let source = member.get("PrincipalSource").and_then(|v| v.as_str()).unwrap_or("");
            
            // Flag domain accounts in local admins
            if source == "ActiveDirectory" && !name.eq_ignore_ascii_case("Domain Admins") {
                findings.push(AdFinding {
                    finding_type: "Privileged Access".to_string(),
                    severity: Severity::Medium,
                    title: format!("Domain User in Local Administrators: {}", name),
                    description: "Domain user added to local Administrators group".to_string(),
                    target: "Local System".to_string(),
                    details: format!("User '{}' from Active Directory is a local administrator", name),
                    remediation: vec![
                        format!("Remove '{}' from local Administrators group", name),
                        "Use Restricted Groups GPO for consistent admin management".to_string(),
                    ],
                });
            }
        }
    }

    Ok(findings)
}

fn scan_linux_ad(runner: &CommandRunner) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    // Check for SSSD/realmd domain join
    let realm_result = runner.run(&["realm", "list"])?;
    if realm_result.returncode == 0 && !realm_result.stdout.trim().is_empty() {
        // Domain joined via realmd/SSSD
        let domain_lines: Vec<&str> = realm_result.stdout.lines()
            .filter(|l| l.contains("domain-name"))
            .collect();
        
        for line in domain_lines {
            if let Some(domain) = line.split(':').nth(1) {
                let domain = domain.trim();
                
                // Check SSSD config for security
                let sssd_config = runner.run(&["cat", "/etc/sssd/sssd.conf"])?;
                if sssd_config.returncode == 0 {
                    let config = sssd_config.stdout;
                    
                    // Check for LDAP TLS
                    if !config.contains("ldap_id_use_start_tls = true") && !config.contains("ldap_uri = ldaps://") {
                        findings.push(AdFinding {
                            finding_type: "LDAP Security".to_string(),
                            severity: Severity::High,
                            title: "LDAP Not Using TLS".to_string(),
                            description: "SSSD configured to use unencrypted LDAP".to_string(),
                            target: format!("Domain: {}", domain),
                            details: "ldap_id_use_start_tls not enabled and ldap_uri not using ldaps://".to_string(),
                            remediation: vec![
                                "Set ldap_id_use_start_tls = true in /etc/sssd/sssd.conf".to_string(),
                                "Or use ldaps:// in ldap_uri".to_string(),
                                "Restart sssd service".to_string(),
                            ],
                        });
                    }

                    // Check for krb5 keytab permissions
                    let keytab_check = runner.run(&["ls", "-la", "/etc/krb5.keytab"])?;
                    if keytab_check.returncode == 0 {
                        let perms = keytab_check.stdout;
                        if perms.contains("root:root") == false && !perms.contains("600") {
                            findings.push(AdFinding {
                                finding_type: "Kerberos Keytab".to_string(),
                                severity: Severity::Medium,
                                title: "Kerberos Keytab Permissions".to_string(),
                                description: "Kerberos keytab file has insecure permissions".to_string(),
                                target: format!("Domain: {}", domain),
                                details: format!("Keytab permissions: {}", perms),
                                remediation: vec![
                                    "chown root:root /etc/krb5.keytab".to_string(),
                                    "chmod 600 /etc/krb5.keytab".to_string(),
                                ],
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for mounted network shares (CIFS/NFS)
    let mounts_result = runner.run(&["mount", "-t", "cifs,nfs,nfs4"])?;
    if mounts_result.returncode == 0 && !mounts_result.stdout.trim().is_empty() {
        for line in mounts_result.stdout.lines() {
            findings.push(AdFinding {
                finding_type: "Network Share Mount".to_string(),
                severity: Severity::Info,
                title: "Network Share Mounted".to_string(),
                description: "Network filesystem mounted on system".to_string(),
                target: "Local System".to_string(),
                details: line.to_string(),
                remediation: vec![
                    "Verify mount options include sec=krb5 or appropriate security".to_string(),
                    "Ensure credentials not stored in /etc/fstab in plaintext".to_string(),
                ],
            });
        }
    }

    // Check /etc/fstab for network mounts
    let fstab_result = runner.run(&["grep", "-E", "cifs|nfs", "/etc/fstab"])?;
    if fstab_result.returncode == 0 {
        for line in fstab_result.stdout.lines() {
            if line.contains("password=") || line.contains("credentials=") && !line.contains("credentials=/etc/") {
                findings.push(AdFinding {
                    finding_type: "Credential Storage".to_string(),
                    severity: Severity::High,
                    title: "Credentials in /etc/fstab".to_string(),
                    description: "Network mount credentials stored in plaintext in /etc/fstab".to_string(),
                    target: "Local System".to_string(),
                    details: line.to_string(),
                    remediation: vec![
                        "Move credentials to /etc/smb.credentials with 600 permissions".to_string(),
                        "Update fstab to use credentials=/etc/smb.credentials".to_string(),
                    ],
                });
            }
        }
    }

    Ok(findings)
}

fn scan_macos_ad(runner: &CommandRunner) -> Result<Vec<AdFinding>> {
    let mut findings = vec![];

    // Check for AD binding via Directory Utility
    let dsconfigad = runner.run(&["dsconfigad", "-show"])?;
    if dsconfigad.returncode == 0 && !dsconfigad.stdout.contains("Active Directory Domain") {
        // Not AD joined
        return Ok(findings);
    }

    if dsconfigad.returncode == 0 {
        let output = dsconfigad.stdout;
        
        // Check for packet signing
        if !output.contains("Packet signing = Enabled") {
            findings.push(AdFinding {
                finding_type: "LDAP Signing".to_string(),
                severity: Severity::High,
                title: "LDAP Packet Signing Disabled".to_string(),
                description: "Mac not enforcing LDAP signing with AD".to_string(),
                target: "Active Directory".to_string(),
                details: "dsconfigad shows packet signing not enabled".to_string(),
                remediation: vec![
                    "sudo dsconfigad -packetencrypt enable".to_string(),
                    "sudo dsconfigad -packetsign enable".to_string(),
                ],
            });
        }

        // Check for namespace mode
        if output.contains("Namespace mode = domain") {
            findings.push(AdFinding {
                finding_type: "Namespace Mode".to_string(),
                severity: Severity::Info,
                title: "Domain Namespace Mode".to_string(),
                description: "Using domain namespace mode (user@domain)".to_string(),
                target: "Active Directory".to_string(),
                details: "Namespace mode is 'domain'".to_string(),
                remediation: vec![],
            });
        }
    }

    // Check for mounted SMB shares
    let mounts_result = runner.run(&["mount", "-t", "smbfs"])?;
    if mounts_result.returncode == 0 && !mounts_result.stdout.trim().is_empty() {
        for line in mounts_result.stdout.lines() {
            findings.push(AdFinding {
                finding_type: "SMB Share Mount".to_string(),
                severity: Severity::Info,
                title: "SMB Share Mounted".to_string(),
                description: "SMB network share mounted via Finder/mount_smbfs".to_string(),
                target: "Active Directory".to_string(),
                details: line.to_string(),
                remediation: vec![
                    "Verify connection uses Kerberos authentication".to_string(),
                    "Check for credential caching in Keychain".to_string(),
                ],
            });
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ad_finding_creation() {
        let finding = AdFinding {
            finding_type: "Test".to_string(),
            severity: Severity::High,
            title: "Test Finding".to_string(),
            description: "Description".to_string(),
            target: "Target".to_string(),
            details: "Details".to_string(),
            remediation: vec!["Fix it".to_string()],
        };
        assert_eq!(finding.severity, Severity::High);
    }
}