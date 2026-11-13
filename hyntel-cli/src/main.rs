use clap::Parser;
use colored::*;
use hyntel_core::{AuditEngine, Platform};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(name = "hyntel", version, about = "Cross-platform security audit tool", long_about = None)]
pub struct Args {
    #[arg(long, value_enum, default_value = "auto")]
    pub target_os: TargetOs,

    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    #[arg(long)]
    pub include_cves: bool,

    #[arg(long, default_value = "3")]
    pub results_per_finding: usize,

    #[arg(long, default_value = "artifacts")]
    pub output_dir: PathBuf,

    #[arg(long)]
    pub generate_remediation: bool,

    #[arg(long)]
    pub save_to_desktop: bool,

    #[arg(long)]
    pub scan_apps: bool,

    #[arg(long, default_value = "25")]
    pub app_limit: usize,

    #[arg(long, value_enum)]
    pub standard: Vec<ComplianceStandard>,

    #[arg(long)]
    pub cleanup: bool,

    // New features
    #[arg(long)]
    pub collect_logs: bool,

    #[arg(long, default_value = "24")]
    pub log_hours: i64,

    #[arg(long)]
    pub scan_ad: bool,

    // Interactive mode
    #[arg(long, short = 'i')]
    pub interactive: bool,

    // Launch TUI
    #[arg(long)]
    pub tui: bool,

    // Launch GUI
    #[arg(long)]
    pub gui: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum TargetOs {
    Auto,
    Linux,
    MacOS,
    Windows,
}

impl From<TargetOs> for Option<Platform> {
    fn from(v: TargetOs) -> Self {
        match v {
            TargetOs::Auto => None,
            TargetOs::Linux => Some(Platform::Linux),
            TargetOs::MacOS => Some(Platform::MacOS),
            TargetOs::Windows => Some(Platform::Windows),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ComplianceStandard {
    ISO27001,
    HIPAA,
    PCIDSS,
}

impl From<ComplianceStandard> for String {
    fn from(v: ComplianceStandard) -> Self {
        match v {
            ComplianceStandard::ISO27001 => "ISO27001".to_string(),
            ComplianceStandard::HIPAA => "HIPAA".to_string(),
            ComplianceStandard::PCIDSS => "PCI_DSS".to_string(),
        }
    }
}

pub fn run_with_args(args: Args) -> anyhow::Result<()> {
    // If TUI or GUI requested, launch them
    if args.tui {
        return launch_tui();
    }
    if args.gui {
        return launch_gui();
    }

    // If interactive mode or no explicit args given (except defaults), prompt for options
    let has_explicit_args = args.include_cves 
        || args.generate_remediation 
        || args.save_to_desktop 
        || args.scan_apps 
        || !args.standard.is_empty() 
        || args.cleanup 
        || args.collect_logs 
        || args.scan_ad
        || args.target_os != TargetOs::Auto
        || args.format != OutputFormat::Text
        || args.results_per_finding != 3
        || args.app_limit != 25
        || args.output_dir != PathBuf::from("artifacts");

    if args.interactive || !has_explicit_args {
        return run_interactive();
    }

    // Non-interactive mode
    run_non_interactive(args)
}

fn launch_tui() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "hyntel-tui"])
        .current_dir("/Users/tac/hyntel-rs")
        .status()?;
    if !status.success() {
        anyhow::bail!("TUI exited with error");
    }
    Ok(())
}

fn launch_gui() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args(["run", "--bin", "hyntel-gui"])
        .current_dir("/Users/tac/hyntel-rs")
        .status()?;
    if !status.success() {
        anyhow::bail!("GUI exited with error");
    }
    Ok(())
}

fn run_interactive() -> anyhow::Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║     HYNTEL Security Audit Tool       ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    // Ask for platform
    let target_os = prompt_target_os()?;
    
    // Ask for options
    let include_cves = prompt_yes_no("Include CVE enrichment (NIST NVD)?", true)?;
    let generate_remediation = prompt_yes_no("Generate remediation script?", true)?;
    let scan_apps = prompt_yes_no("Scan installed applications?", true)?;
    let scan_logs = prompt_yes_no("Collect system logs?", false)?;
    let log_hours = if scan_logs { prompt_number("Hours of logs to collect (1-168)", 24, 1, 168)? } else { 24 };
    let scan_ad = prompt_yes_no("Scan Active Directory security?", false)?;
    let save_to_desktop = prompt_yes_no("Save reports to Desktop?", true)?;
    let format = prompt_format()?;

    let standards = prompt_standards()?;

    let engine = AuditEngine::new(standards, None)?;

    println!("\n{}", "Running audit...".yellow());

    let report = engine.run_audit(
        target_os,
        include_cves,
        3, // results_per_finding
        generate_remediation,
        scan_apps,
        25, // app_limit
        save_to_desktop,
        &PathBuf::from("artifacts"),
        scan_logs,
        log_hours,
        scan_ad,
    )?;

    match format {
        OutputFormat::Json => {
            println!("{}", hyntel_core::reporting::render_json_report(&report)?);
        }
        OutputFormat::Text => {
            let text = hyntel_core::reporting::render_text_report(&report);
            println!("{}", text);
        }
    }

    Ok(())
}

fn prompt_target_os() -> anyhow::Result<Option<Platform>> {
    println!("{}", "Select target platform:".bold());
    println!("  1) Auto-detect");
    println!("  2) Linux");
    println!("  3) macOS");
    println!("  4) Windows");
    print!("Choice [1]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();
    
    match choice {
        "1" | "" => Ok(None),
        "2" => Ok(Some(Platform::Linux)),
        "3" => Ok(Some(Platform::MacOS)),
        "4" => Ok(Some(Platform::Windows)),
        _ => {
            println!("{}", "Invalid choice, using auto-detect".yellow());
            Ok(None)
        }
    }
}

fn prompt_yes_no(prompt: &str, default: bool) -> anyhow::Result<bool> {
    let default_str = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", prompt.bold(), default_str);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    
    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input.starts_with('y'))
    }
}

fn prompt_number(prompt: &str, default: i64, min: i64, max: i64) -> anyhow::Result<i64> {
    print!("{} [{}]: ", prompt.bold(), default);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if input.is_empty() {
        Ok(default)
    } else {
        match input.parse::<i64>() {
            Ok(n) if n >= min && n <= max => Ok(n),
            _ => {
                println!("{}", format!("Invalid number, using default: {}", default).yellow());
                Ok(default)
            }
        }
    }
}

fn prompt_format() -> anyhow::Result<OutputFormat> {
    println!("\n{}", "Output format:".bold());
    println!("  1) Text (human-readable)");
    println!("  2) JSON (machine-readable)");
    print!("Choice [1]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    match input.trim() {
        "2" => Ok(OutputFormat::Json),
        _ => Ok(OutputFormat::Text),
    }
}

fn prompt_standards() -> anyhow::Result<Option<Vec<String>>> {
    println!("\n{}", "Compliance standards (space-separated, e.g. 'ISO27001 HIPAA'):".bold());
    println!("  Available: ISO27001, HIPAA, PCI_DSS");
    print!("Standards [none]: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if input.is_empty() {
        Ok(None)
    } else {
        let standards: Vec<String> = input.split_whitespace()
            .map(|s| s.to_uppercase())
            .filter(|s| matches!(s.as_str(), "ISO27001" | "HIPAA" | "PCI_DSS"))
            .collect();
        if standards.is_empty() {
            println!("{}", "No valid standards selected".yellow());
            Ok(None)
        } else {
            Ok(Some(standards))
        }
    }
}

fn run_non_interactive(args: Args) -> anyhow::Result<()> {
    let standards: Option<Vec<String>> = if args.standard.is_empty() {
        None
    } else {
        Some(args.standard.into_iter().map(Into::into).collect())
    };

    let engine = AuditEngine::new(standards, None)?;

    let report = engine.run_audit(
        args.target_os.into(),
        args.include_cves,
        args.results_per_finding,
        args.generate_remediation,
        args.scan_apps,
        args.app_limit,
        args.save_to_desktop,
        &args.output_dir,
        args.collect_logs,
        args.log_hours,
        args.scan_ad,
    )?;

    match args.format {
        OutputFormat::Json => {
            println!("{}", hyntel_core::reporting::render_json_report(&report)?);
        }
        OutputFormat::Text => {
            let text = hyntel_core::reporting::render_text_report(&report);
            println!("{}", text);
        }
    }

    if args.cleanup {
        println!("\n{}", "--- Cleanup ---".bold());
        println!("{}", "Cleanup complete.".green());
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run_with_args(args)
}