use anyhow::{Context, Result};
use sysinfo::System;
use crate::models::{OsInfo, Platform};
use crate::command_runner::CommandRunner;

pub fn detect_platform() -> Platform {
    Platform::detect()
}

pub fn detect_os_info(runner: Option<&CommandRunner>) -> Result<OsInfo> {
    let platform = detect_platform();
    let sys = System::new_all();

    match platform {
        Platform::Linux => detect_linux_os_info(&sys),
        Platform::MacOS => detect_macos_os_info(&sys),
        Platform::Windows => detect_windows_os_info(runner, &sys),
        Platform::Unknown => Ok(OsInfo {
            name: "Unknown".to_string(),
            version: std::env::consts::OS.to_string(),
            architecture: Some(std::env::consts::ARCH.to_string()),
            build: None,
            kernel: None,
            security_patches: vec![],
        }),
    }
}

fn detect_linux_os_info(_sys: &System) -> Result<OsInfo> {
    let mut name = "Linux".to_string();
    let mut version = "unknown".to_string();

    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim_matches('"');
                match key {
                    "NAME" => name = value.to_string(),
                    "VERSION" | "VERSION_ID" => version = value.to_string(),
                    _ => {}
                }
            }
        }
    }

    Ok(OsInfo {
        name,
        version,
        architecture: System::cpu_arch(),
        build: None,
        kernel: Some(System::kernel_version().unwrap_or_default()),
        security_patches: vec![],
    })
}

fn detect_macos_os_info(_sys: &System) -> Result<OsInfo> {
    let version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let mut build = None;
    let mut product_name = "macOS".to_string();

    if let Ok(output) = std::process::Command::new("sw_vers").arg("-productName").output() {
        if output.status.success() {
            product_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    if let Ok(output) = std::process::Command::new("sw_vers").arg("-buildVersion").output() {
        if output.status.success() {
            build = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }

    Ok(OsInfo {
        name: product_name,
        version,
        architecture: System::cpu_arch(),
        build,
        kernel: Some(System::kernel_version().unwrap_or_default()),
        security_patches: vec![],
    })
}

fn detect_windows_os_info(runner: Option<&CommandRunner>, _sys: &System) -> Result<OsInfo> {
    let runner_ref: &CommandRunner = runner.unwrap_or_else(|| {
        static DEFAULT_RUNNER: std::sync::OnceLock<CommandRunner> = std::sync::OnceLock::new();
        DEFAULT_RUNNER.get_or_init(CommandRunner::new)
    });
    let mut name = "Windows".to_string();
    let version = System::os_version().unwrap_or_else(|| std::env::consts::OS.to_string());
    let architecture = System::cpu_arch();
    let mut build = None;
    let mut patches = vec![];

    // Get OS details via PowerShell
    let os_result = runner_ref.run_shell(
        r#"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json -Compress"#,
    )?;

    if os_result.returncode == 0 && !os_result.stdout.is_empty() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&os_result.stdout) {
            if let Some(caption) = json.get("Caption").and_then(|v| v.as_str()) {
                name = caption.to_string();
            }
            if let Some(_ver) = json.get("Version").and_then(|v| v.as_str()) {
                // version already detected from sysinfo
            }
            if let Some(b) = json.get("BuildNumber").and_then(|v| v.as_str()) {
                build = Some(b.to_string());
            }
            if let Some(_arch) = json.get("OSArchitecture").and_then(|v| v.as_str()) {
                // architecture already detected
            }
        }
    }

    // Get installed hotfixes
    let patch_result = runner_ref.run_shell(
        r#"Get-HotFix | Select-Object -ExpandProperty HotFixID | Sort-Object"#,
    )?;

    if patch_result.returncode == 0 && !patch_result.stdout.is_empty() {
        patches = patch_result
            .stdout
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    Ok(OsInfo {
        name,
        version,
        architecture,
        build,
        kernel: None,
        security_patches: patches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        assert_ne!(platform, Platform::Unknown);
    }
}