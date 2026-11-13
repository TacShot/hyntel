use eframe::egui;
use hyntel_core::{AuditEngine, AuditReport, Platform};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
enum TimeFrame {
    Hours24,
    Hours48,
    Hours72,
    Custom,
}

impl TimeFrame {
    fn label(&self) -> &'static str {
        match self {
            TimeFrame::Hours24 => "24 hours",
            TimeFrame::Hours48 => "48 hours",
            TimeFrame::Hours72 => "72 hours",
            TimeFrame::Custom => "Custom hours...",
        }
    }

    fn hours(&self) -> i64 {
        match self {
            TimeFrame::Hours24 => 24,
            TimeFrame::Hours48 => 48,
            TimeFrame::Hours72 => 72,
            TimeFrame::Custom => 24,
        }
    }
}

#[derive(Clone)]
struct AuditConfig {
    target_os: String,
    include_cves: bool,
    generate_remediation: bool,
    scan_apps: bool,
    save_to_desktop: bool,
    cve_limit: usize,
    app_limit: usize,
    standards: Vec<String>,
    output_dir: PathBuf,
    collect_logs: bool,
    time_frame: TimeFrame,
    log_hours: i64,
    scan_ad: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            target_os: "auto".to_string(),
            include_cves: true,
            generate_remediation: true,
            scan_apps: true,
            save_to_desktop: false,
            cve_limit: 3,
            app_limit: 25,
            standards: vec![],
            output_dir: PathBuf::from("artifacts"),
            collect_logs: false,
            time_frame: TimeFrame::Hours24,
            log_hours: 24,
            scan_ad: false,
        }
    }
}

struct HyntelApp {
    config: AuditConfig,
    report: Option<Arc<Mutex<Option<AuditReport>>>>,
    scan_thread: Option<thread::JoinHandle<()>>,
    status: String,
    progress: f32,
    show_results: bool,
    selected_tab: usize,
    scroll_offset: usize,
}

impl HyntelApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Custom dark theme - limited palette: white, black, gray, green, yellow, red, orange
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals.dark_mode = true;
        style.visuals.panel_fill = egui::Color32::from_rgb(0x1f, 0x24, 0x27);
        style.visuals.window_fill = egui::Color32::from_rgb(0x26, 0x2c, 0x30);
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(0x1f, 0x24, 0x27);
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(0x26, 0x2c, 0x30);
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x2f, 0x36, 0x3b);
        // Orange accent instead of blue
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0xff, 0xa5, 0x00);
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(0xff, 0xa5, 0x00);
        cc.egui_ctx.set_style(style);

        Self {
            config: AuditConfig::default(),
            report: None,
            scan_thread: None,
            status: "READY".to_string(),
            progress: 0.0,
            show_results: false,
            selected_tab: 0,
            scroll_offset: 0,
        }
    }

    fn start_scan(&mut self) {
        let config = self.config.clone();
        let report = Arc::new(Mutex::new(None));
        let report_clone = report.clone();

        self.status = "SCANNING...".to_string();
        self.progress = 0.0;
        self.show_results = false;
        self.report = Some(report);

        let handle = thread::spawn(move || {
            let engine = AuditEngine::new(None, None).unwrap();
            let hours = match config.time_frame {
                TimeFrame::Custom => config.log_hours,
                _ => config.time_frame.hours(),
            };
            let result = engine.run_audit(
                match config.target_os.as_str() {
                    "linux" => Some(Platform::Linux),
                    "macos" => Some(Platform::MacOS),
                    "windows" => Some(Platform::Windows),
                    _ => None,
                },
                config.include_cves,
                config.cve_limit,
                config.generate_remediation,
                config.scan_apps,
                config.app_limit,
                config.save_to_desktop,
                &config.output_dir,
                config.collect_logs,
                hours,
                config.scan_ad,
            );

            if let Ok(report) = result {
                *report_clone.lock().unwrap() = Some(report);
            }
        });

        self.scan_thread = Some(handle);
    }
}

impl eframe::App for HyntelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check scan completion
        if let Some(handle) = &self.scan_thread {
            if handle.is_finished() {
                self.status = "COMPLETE".to_string();
                self.progress = 1.0;
                self.show_results = true;
                self.scan_thread = None;
            } else {
                self.progress += 0.01;
                if self.progress > 0.95 {
                    self.progress = 0.95;
                }
            }
        }

        // Top bar
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("HYNTEL").color(egui::Color32::from_rgb(0xff, 0xa5, 0x00)).strong());
                ui.label(egui::RichText::new("Security Audit Terminal").color(egui::Color32::from_rgb(0x88, 0x88, 0x88)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(&self.status).color(if self.status == "COMPLETE" { egui::Color32::GREEN } else { egui::Color32::YELLOW }).strong());
                });
            });
            ui.separator();
        });

        // Main content
        if self.show_results {
            self.show_results_panel(ctx);
        } else {
            self.show_config_panel(ctx);
        }

        // Bottom status bar
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::ProgressBar::new(self.progress).show_percentage().desired_width(200.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("F1 Help  Esc Back  Ctrl+Q Quit").color(egui::Color32::from_rgb(0x88, 0x88, 0x88)));
                });
            });
        });

        // Request repaint for progress animation
        if self.scan_thread.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl HyntelApp {
    fn show_config_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.heading("Security Audit Configuration");
                ui.add_space(20.0);

                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                    .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x88, 0x88, 0x88)))
                    .show(ui, |ui| {
                        ui.set_max_width(500.0);
                        ui.vertical(|ui| {
                            ui.add_space(10.0);

                            // Target OS
                            ui.horizontal(|ui| {
                                ui.label("Target OS:");
                                ui.push_id("target_os_combo", |ui| {
                                egui::ComboBox::from_label("")
                                    .selected_text(&self.config.target_os)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.config.target_os, "auto".to_string(), "Auto-detect");
                                        ui.selectable_value(&mut self.config.target_os, "linux".to_string(), "Linux");
                                        ui.selectable_value(&mut self.config.target_os, "macos".to_string(), "macOS");
                                        ui.selectable_value(&mut self.config.target_os, "windows".to_string(), "Windows");
                                    });
                            });
                            });
                            ui.add_space(10.0);

                            // Checkboxes
                            ui.checkbox(&mut self.config.include_cves, "Include CVE enrichment (NIST NVD)");
                            ui.checkbox(&mut self.config.generate_remediation, "Generate remediation script");
                            ui.checkbox(&mut self.config.scan_apps, "Scan installed applications");
                            ui.checkbox(&mut self.config.save_to_desktop, "Save reports to Desktop");
                            ui.push_id("collect_logs_checkbox", |ui| {
                                ui.checkbox(&mut self.config.collect_logs, "Collect system logs");
                            });
                            ui.push_id("scan_ad_checkbox", |ui| {
                                ui.checkbox(&mut self.config.scan_ad, "Scan Active Directory security");
                            });
                            ui.add_space(10.0);

                            // Time Frame selector
                            if self.config.collect_logs {
                                ui.horizontal(|ui| {
                                    ui.label("Log time frame:");
                                    ui.push_id("log_time_frame_combo", |ui| {
                                        egui::ComboBox::from_label("")
                                            .selected_text(self.config.time_frame.label())
                                            .show_ui(ui, |ui| {
                                                ui.selectable_value(&mut self.config.time_frame, TimeFrame::Hours24, "24 hours");
                                                ui.selectable_value(&mut self.config.time_frame, TimeFrame::Hours48, "48 hours");
                                                ui.selectable_value(&mut self.config.time_frame, TimeFrame::Hours72, "72 hours");
                                                ui.selectable_value(&mut self.config.time_frame, TimeFrame::Custom, "Custom hours...");
                                            });
                                    });
                                });
                                if self.config.time_frame == TimeFrame::Custom {
                                    ui.horizontal(|ui| {
                                        ui.label("Custom hours:");
                                        ui.add(egui::DragValue::new(&mut self.config.log_hours).range(1..=168).suffix("h"));
                                    });
                                }
                            }
                            ui.add_space(10.0);

                            // Limits
                            ui.horizontal(|ui| {
                                ui.label("CVE results per finding:");
                                ui.add(egui::DragValue::new(&mut self.config.cve_limit).range(1..=10));
                            });
                            ui.horizontal(|ui| {
                                ui.label("Max applications to scan:");
                                ui.add(egui::DragValue::new(&mut self.config.app_limit).range(1..=100));
                            });
                            ui.add_space(10.0);

                            // Standards
                            ui.horizontal(|ui| {
                                ui.label("Compliance standards:");
                                for std in ["ISO27001", "HIPAA", "PCI_DSS"] {
                                    let mut selected = self.config.standards.contains(&std.to_string());
                                    if ui.checkbox(&mut selected, std).changed() {
                                        if selected {
                                            self.config.standards.push(std.to_string());
                                        } else {
                                            self.config.standards.retain(|s| s != std);
                                        }
                                    }
                                }
                            });
                            ui.add_space(20.0);

                            // Run button
                            if ui.add_sized([200.0, 40.0], egui::Button::new(egui::RichText::new("RUN AUDIT").size(18.0).strong())).clicked() {
                                self.start_scan();
                            }
                        });
                    });
            });
        });
    }
}

impl HyntelApp {
    fn show_results_panel(&mut self, ctx: &egui::Context) {
        let report = self.report.as_ref().and_then(|r| r.lock().ok()).and_then(|r| r.as_ref().cloned());
        let Some(report) = report else { return };

        // Top tab bar
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (i, tab) in ["Summary", "Findings", "Applications", "Processes", "Remediation", "System Logs", "AD Findings"].iter().enumerate() {
                    let selected = i == self.selected_tab;
                    let response = ui.selectable_label(selected, *tab);
                    if response.clicked() {
                        self.selected_tab = i;
                        self.scroll_offset = 0;
                    }
                }
            });
        });

        // Content area
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.selected_tab {
                    0 => self.render_summary(ui, &report),
                    1 => self.render_findings(ui, &report),
                    2 => self.render_applications(ui, &report),
                    3 => self.render_processes(ui, &report),
                    4 => self.render_remediation(ui, &report),
                    5 => self.render_system_logs(ui, &report),
                    6 => self.render_ad_findings(ui, &report),
                    _ => {}
                }
            });
        });
    }

    fn render_summary(&self, ui: &mut egui::Ui, report: &AuditReport) {
        let summary = hyntel_core::reporting::summarize_results(&report.results);

        ui.heading("Audit Summary");
        ui.add_space(10.0);

        egui::Grid::new("summary_grid").num_columns(2).show(ui, |ui| {
            ui.label("Platform:");
            ui.label(platform_to_str(&report.target_platform));
            ui.end_row();

            ui.label("OS:");
            ui.label(&report.os_info.name);
            ui.end_row();

            ui.label("Version:");
            ui.label(&report.os_info.version);
            ui.end_row();

            if let Some(arch) = &report.os_info.architecture {
                ui.label("Architecture:");
                ui.label(arch);
                ui.end_row();
            }

            ui.label("Passed:");
            ui.colored_label(egui::Color32::GREEN, summary.passed.to_string());
            ui.end_row();

            ui.label("Failed:");
            ui.colored_label(egui::Color32::RED, summary.failed.to_string());
            ui.end_row();

            ui.label("Skipped:");
            ui.colored_label(egui::Color32::YELLOW, summary.skipped.to_string());
            ui.end_row();
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);

        // Severity breakdown
        ui.heading("Findings by Severity");
        let mut severity_counts = std::collections::HashMap::new();
        for (rule, result) in &report.results {
            if result.status == hyntel_core::models::CheckStatus::Fail {
                *severity_counts.entry(rule.severity.clone()).or_insert(0) += 1;
            }
        }

        egui::Grid::new("severity_grid").num_columns(2).show(ui, |ui| {
            // Sort by severity order: Critical > High > Medium > Low > Info
            let severity_order = [
                hyntel_core::models::Severity::Critical,
                hyntel_core::models::Severity::High,
                hyntel_core::models::Severity::Medium,
                hyntel_core::models::Severity::Low,
                hyntel_core::models::Severity::Info,
            ];
            for severity in severity_order {
                if let Some(count) = severity_counts.get(&severity) {
                    ui.label(format!("{:?}:", severity));
                    ui.colored_label(severity_color(&severity), count.to_string());
                    ui.end_row();
                }
            }
        });
    }

    fn render_findings(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("Detailed Findings");
        ui.add_space(10.0);

        for (rule, result) in &report.results {
            let status_color = match result.status {
                hyntel_core::models::CheckStatus::Pass => egui::Color32::GREEN,
                hyntel_core::models::CheckStatus::Fail => egui::Color32::RED,
                hyntel_core::models::CheckStatus::Skip => egui::Color32::YELLOW,
            };

            egui::Frame::default()
                .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                .stroke(egui::Stroke::new(1.0_f32, status_color))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(status_color, format!("{:?}", result.status));
                        ui.strong(&rule.title);
                        ui.label(format!("({:?})", rule.severity));
                    });
                    ui.add_space(5.0);
                    ui.label(format!("Rule ID: {}", rule.id));
                    ui.label(format!("Description: {}", rule.description));
                    ui.label(format!("Rationale: {}", rule.rationale));
                    ui.label(format!("Details: {}", result.details));

                    if let Some(observed) = &result.observed_value {
                        ui.label(format!("Observed: {}", observed));
                    }

                    if !result.remediation.is_empty() {
                        ui.add_space(5.0);
                        ui.strong("Remediation:");
                        for action in &result.remediation {
                            ui.label(format!("  • {}", action));
                        }
                    }

                    if !result.related_cves.is_empty() {
                        ui.add_space(5.0);
                        ui.strong("Related CVEs:");
                        for cve in &result.related_cves {
                            let id = cve.id.as_deref().unwrap_or("unknown");
                            let severity = cve.severity.as_deref().unwrap_or("unknown");
                            ui.label(format!("  • {} ({})", id, severity));
                            if !cve.description.is_empty() {
                                ui.label(format!("    {}", cve.description));
                            }
                        }
                    }
                });
            ui.add_space(10.0);
        }
    }

    fn render_applications(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("Installed Applications");
        ui.add_space(10.0);

        if report.scanned_applications.is_empty() {
            ui.label("No applications scanned. Enable 'Scan installed applications' in configuration.");
            return;
        }

        for app in &report.scanned_applications {
            ui.label(format!("{} {} [{}]", app.name, app.version, app.source));
        }

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);

        if !report.application_findings.is_empty() {
            ui.heading("Application CVE Findings");
            for finding in &report.application_findings {
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                    .show(ui, |ui| {
                        ui.strong(format!("{} {}", finding.application.name, finding.application.version));
                        if let Some(cpe) = &finding.cpe_name {
                            ui.label(format!("CPE: {}", cpe));
                        }
                        for cve in &finding.cves {
                            let id = cve.id.as_deref().unwrap_or("unknown");
                            let severity = cve.severity.as_deref().unwrap_or("unknown");
                            ui.colored_label(severity_color_from_str(severity), format!("  • {} ({})", id, severity));
                        }
                    });
                ui.add_space(5.0);
            }
        }
    }

    fn render_processes(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("Running Processes");
        ui.add_space(10.0);

        if report.scanned_processes.is_empty() {
            ui.label("No processes scanned.");
            return;
        }

        for proc in &report.scanned_processes {
            let exe = proc.executable.as_deref().unwrap_or("unknown");
            ui.label(format!("PID {}: {} [{}]", proc.pid, proc.name, exe));
        }

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);

        if !report.process_findings.is_empty() {
            ui.heading("Process Findings");
            for finding in &report.process_findings {
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                    .stroke(egui::Stroke::new(1.0_f32, severity_color(&finding.severity)))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!("PID {}: {}", finding.process.pid, finding.process.name));
                            ui.colored_label(severity_color(&finding.severity), format!("{:?}", finding.severity));
                        });
                        for reason in &finding.reasons {
                            ui.label(format!("  • {}", reason));
                        }
                        if let Some(action) = &finding.recommended_action {
                            ui.label(format!("  Action: {}", action));
                        }
                    });
                ui.add_space(5.0);
            }
        }
    }

    fn render_remediation(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("Remediation");
        ui.add_space(10.0);

        if let Some(path) = &report.remediation_path {
            ui.label(format!("Script generated: {}", path));
            ui.add_space(10.0);
            ui.label("Review the script before executing:");
            ui.add_space(5.0);

            // Show script content
            if let Ok(content) = std::fs::read_to_string(path) {
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x1f, 0x24, 0x27))
                    .show(ui, |ui| {
                        ui.add_sized(
                            [ui.available_width(), 400.0],
                            egui::TextEdit::multiline(&mut content.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(20)
                                .interactive(false),
                        );
                    });
            }
        } else {
            ui.label("No remediation script generated (no failed checks or option disabled).");
        }
    }

    fn render_system_logs(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("System Logs");
        ui.add_space(10.0);

        if report.system_logs.is_empty() {
            ui.label("No system logs collected. Enable 'Collect system logs' in configuration.");
            return;
        }

        for log in &report.system_logs {
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("[{}]", log.timestamp.format("%Y-%m-%d %H:%M:%S")));
                        ui.colored_label(egui::Color32::from_rgb(0xb7, 0xc0, 0xc8), &log.level);
                        ui.strong(&log.source);
                    });
                    ui.label(&log.message);
                    if let Some(unit) = &log.unit {
                        ui.label(format!("Unit: {}", unit));
                    }
                    if let Some(pid) = log.pid {
                        ui.label(format!("PID: {}", pid));
                    }
                    if let Some(user) = &log.user {
                        ui.label(format!("User: {}", user));
                    }
                });
            ui.add_space(5.0);
        }
    }

    fn render_ad_findings(&self, ui: &mut egui::Ui, report: &AuditReport) {
        ui.heading("Active Directory Findings");
        ui.add_space(10.0);

        if report.ad_findings.is_empty() {
            if self.config.scan_ad {
                ui.label("No Active Directory findings detected.");
                ui.label("This system is not joined to an Active Directory domain, or no AD security issues were detected.");
                ui.add_space(5.0);
                ui.label("To enable AD security scanning, join this system to an AD domain and re-run the scan.");
            } else {
                ui.label("No AD findings. Enable 'Scan Active Directory security' in configuration to scan for AD security issues.");
            }
            return;
        }

        for finding in &report.ad_findings {
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(0x26, 0x2c, 0x30))
                .stroke(egui::Stroke::new(1.0_f32, severity_color(&finding.severity)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&finding.title);
                        ui.colored_label(severity_color(&finding.severity), format!("[{:?}]", finding.severity));
                    });
                    ui.label(format!("Type: {}", finding.finding_type));
                    ui.label(format!("Target: {}", finding.target));
                    ui.label(format!("Description: {}", finding.description));
                    ui.label(format!("Details: {}", finding.details));
                    if !finding.remediation.is_empty() {
                        ui.add_space(5.0);
                        ui.strong("Remediation:");
                        for action in &finding.remediation {
                            ui.label(format!("  • {}", action));
                        }
                    }
                });
            ui.add_space(5.0);
        }
    }
}

fn platform_to_str(platform: &Platform) -> &'static str {
    match platform {
        Platform::Linux => "Linux",
        Platform::MacOS => "macOS",
        Platform::Windows => "Windows",
        Platform::Unknown => "Unknown",
    }
}

fn severity_color(severity: &hyntel_core::models::Severity) -> egui::Color32 {
    match severity {
        hyntel_core::models::Severity::Critical => egui::Color32::from_rgb(0xff, 0x44, 0x44),
        hyntel_core::models::Severity::High => egui::Color32::from_rgb(0xff, 0x88, 0x44),
        hyntel_core::models::Severity::Medium => egui::Color32::from_rgb(0xff, 0xdd, 0x44),
        hyntel_core::models::Severity::Low => egui::Color32::from_rgb(0x44, 0xdd, 0x44),
        hyntel_core::models::Severity::Info => egui::Color32::from_rgb(0x44, 0x88, 0xff),
    }
}

fn severity_color_from_str(severity: &str) -> egui::Color32 {
    match severity.to_lowercase().as_str() {
        "critical" => egui::Color32::from_rgb(0xff, 0x44, 0x44),
        "high" => egui::Color32::from_rgb(0xff, 0x88, 0x44),
        "medium" => egui::Color32::from_rgb(0xff, 0xdd, 0x44),
        "low" => egui::Color32::from_rgb(0x44, 0xdd, 0x44),
        _ => egui::Color32::from_rgb(0x44, 0x88, 0xff),
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("HYNTEL - Security Audit Terminal"),
        ..Default::default()
    };

    eframe::run_native(
        "HYNTEL",
        options,
        Box::new(|cc| Ok(Box::new(HyntelApp::new(cc)))),
    )
}
