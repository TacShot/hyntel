use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{stdout, Stdout};
use std::fs;
use std::path::PathBuf;
use hyntel_core::{AuditEngine, AuditReport, Platform};
use dirs;
use chrono;

// Color palette: white, black, gray, green, yellow, red, orange
const ORANGE: Color = Color::Rgb(255, 165, 0);
const GRAY: Color = Color::DarkGray;

#[derive(Default)]
enum AppState {
    #[default]
    MainMenu,
    Configure,
    RunAudit,
    Running,
    Results(AuditReport),
    ViewLastReport,
    OutputLocation,
    Error(String),
}

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
            TimeFrame::Custom => "Custom...",
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

struct Config {
    target_os: Option<Platform>,
    include_cves: bool,
    generate_remediation: bool,
    scan_apps: bool,
    save_to_desktop: bool,
    collect_logs: bool,
    time_frame: TimeFrame,
    custom_hours: i64,
    scan_ad: bool,
    standards: Vec<String>,
    output_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_os: None,
            include_cves: true,
            generate_remediation: true,
            scan_apps: true,
            save_to_desktop: true,
            collect_logs: false,
            time_frame: TimeFrame::Hours24,
            custom_hours: 24,
            scan_ad: false,
            standards: vec![],
            output_dir: PathBuf::from("artifacts"),
        }
    }
}

struct App {
    state: AppState,
    engine: AuditEngine,
    config: Config,
    selected_main: usize,
    selected_config: usize,
    selected_output: usize,
    selected_report: usize,
    scroll_offset: usize,
    last_report_path: Option<PathBuf>,
    custom_input: String,
    input_mode: bool,
}

impl App {
    fn new() -> Result<Self> {
        let engine = AuditEngine::new(None, None)?;
        Ok(Self {
            state: AppState::MainMenu,
            engine,
            config: Config::default(),
            selected_main: 0,
            selected_config: 0,
            selected_output: 0,
            selected_report: 0,
            scroll_offset: 0,
            last_report_path: None,
            custom_input: String::new(),
            input_mode: false,
        })
    }

    fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|frame| self.render(frame))?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match self.handle_key(key.code) {
                        Ok(should_exit) => {
                            if should_exit {
                                break;
                            }
                        }
                        Err(e) => {
                            self.state = AppState::Error(e.to_string());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyCode) -> Result<bool> {
        if self.input_mode {
            return self.handle_input_key(key);
        }

        match &self.state {
            AppState::MainMenu => match key {
                KeyCode::Up => {
                    if self.selected_main >= 2 {
                        self.selected_main -= 2;
                    }
                }
                KeyCode::Down => {
                    if self.selected_main < 4 {
                        self.selected_main += 2;
                    }
                }
                KeyCode::Left => {
                    if self.selected_main % 2 == 1 {
                        self.selected_main -= 1;
                    }
                }
                KeyCode::Right => {
                    if self.selected_main % 2 == 0 && self.selected_main < 5 {
                        self.selected_main += 1;
                    }
                }
                KeyCode::Enter => {
                    match self.selected_main {
                        0 => self.state = AppState::Configure,       // Run Audit (configure first)
                        1 => self.state = AppState::Configure,       // Configure Options
                        2 => self.load_last_report()?,               // View Last Report
                        3 => self.state = AppState::OutputLocation,  // Output Reports Location
                        4 => self.show_help()?,                      // Help
                        5 => return Ok(true),                        // Exit
                        _ => {}
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => return Ok(true),
                _ => {}
            },
            AppState::Configure => match key {
                KeyCode::Up => {
                    if self.selected_config >= 2 {
                        self.selected_config -= 2;
                    }
                }
                KeyCode::Down => {
                    if self.selected_config < 11 {
                        self.selected_config += 2;
                    }
                }
                KeyCode::Left => {
                    if self.selected_config % 2 == 1 {
                        self.selected_config -= 1;
                    }
                }
                KeyCode::Right => {
                    if self.selected_config % 2 == 0 && self.selected_config < 12 {
                        self.selected_config += 1;
                    }
                }
                KeyCode::Enter => {
                    self.toggle_config_option(self.selected_config)?;
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.state = AppState::RunAudit;
                    self.run_audit()?;
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.state = AppState::MainMenu;
                }
                _ => {}
            },
            AppState::RunAudit => match key {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.state = AppState::MainMenu;
                }
                _ => {}
            },
            AppState::Running => {},
            AppState::Results(_) => match key {
                KeyCode::Up => {
                    if self.scroll_offset > 0 {
                        self.scroll_offset -= 1;
                    }
                }
                KeyCode::Down => {
                    self.scroll_offset += 1;
                }
                KeyCode::PageUp => {
                    self.scroll_offset = self.scroll_offset.saturating_sub(10);
                }
                KeyCode::PageDown => {
                    self.scroll_offset += 10;
                }
                KeyCode::Home => {
                    self.scroll_offset = 0;
                }
                KeyCode::End => {
                    self.scroll_offset = usize::MAX;
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.state = AppState::MainMenu;
                    self.scroll_offset = 0;
                }
                _ => {}
            },
            AppState::ViewLastReport => match key {
                KeyCode::Up => {
                    if self.selected_report > 0 {
                        self.selected_report -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.selected_report < 2 {
                        self.selected_report += 1;
                    }
                }
                KeyCode::Enter => {
                    match self.selected_report {
                        0 => self.open_report()?,
                        1 => self.open_report_dir()?,
                        2 => self.state = AppState::MainMenu,
                        _ => {}
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.state = AppState::MainMenu;
                }
                _ => {}
            },
            AppState::OutputLocation => match key {
                KeyCode::Up => {
                    if self.selected_output > 0 {
                        self.selected_output -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.selected_output < 2 {
                        self.selected_output += 1;
                    }
                }
                KeyCode::Enter => {
                    match self.selected_output {
                        0 => self.open_output_dir()?,
                        1 => self.change_output_dir()?,
                        2 => self.state = AppState::MainMenu,
                        _ => {}
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.state = AppState::MainMenu;
                }
                _ => {}
            },
            AppState::Error(_) => match key {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.state = AppState::MainMenu;
                }
                _ => {}
            },
        }
        Ok(false)
    }

    fn handle_input_key(&mut self, key: KeyCode) -> Result<bool> {
        match key {
            KeyCode::Enter => {
                self.input_mode = false;
                if !self.custom_input.is_empty() {
                    if let Ok(hours) = self.custom_input.parse::<i64>() {
                        self.config.custom_hours = hours.clamp(1, 168);
                        if self.config.time_frame == TimeFrame::Custom {
                            // Already set
                        }
                    }
                    self.custom_input.clear();
                }
            }
            KeyCode::Esc => {
                self.input_mode = false;
                self.custom_input.clear();
            }
            KeyCode::Char(c) => {
                if c.is_ascii_digit() {
                    self.custom_input.push(c);
                }
            }
            KeyCode::Backspace => {
                self.custom_input.pop();
            }
            _ => {}
        }
        Ok(false)
    }

    fn toggle_config_option(&mut self, index: usize) -> Result<()> {
        match index {
            0 => self.config.target_os = match self.config.target_os {
                None => Some(Platform::Linux),
                Some(Platform::Linux) => Some(Platform::MacOS),
                Some(Platform::MacOS) => Some(Platform::Windows),
                Some(Platform::Windows) => None,
                Some(Platform::Unknown) => Some(Platform::Linux),
            },
            1 => self.config.include_cves = !self.config.include_cves,
            2 => self.config.generate_remediation = !self.config.generate_remediation,
            3 => self.config.scan_apps = !self.config.scan_apps,
            4 => self.config.save_to_desktop = !self.config.save_to_desktop,
            5 => self.config.collect_logs = !self.config.collect_logs,
            6 => {
                self.config.time_frame = match self.config.time_frame {
                    TimeFrame::Hours24 => TimeFrame::Hours48,
                    TimeFrame::Hours48 => TimeFrame::Hours72,
                    TimeFrame::Hours72 => TimeFrame::Custom,
                    TimeFrame::Custom => TimeFrame::Hours24,
                };
            }
            7 => {
                if self.config.time_frame == TimeFrame::Custom {
                    self.input_mode = true;
                    self.custom_input.clear();
                }
            }
            8 => self.config.scan_ad = !self.config.scan_ad,
            9 => {
                // Cycle through standards
                let all = ["ISO27001", "HIPAA", "PCI_DSS"];
                if self.config.standards.is_empty() {
                    self.config.standards = vec![all[0].to_string()];
                } else if self.config.standards.len() == 1 {
                    self.config.standards = vec![all[0].to_string(), all[1].to_string()];
                } else if self.config.standards.len() == 2 {
                    self.config.standards = vec![all[0].to_string(), all[1].to_string(), all[2].to_string()];
                } else {
                    self.config.standards.clear();
                }
            }
            10 => {
                self.state = AppState::OutputLocation;
            }
            11 => {
                self.state = AppState::RunAudit;
                self.run_audit()?;
            }
            12 => {
                self.state = AppState::MainMenu;
            }
            _ => {}
        }
        Ok(())
    }

    fn load_last_report(&mut self) -> Result<()> {
        let artifacts = PathBuf::from("artifacts");
        if let Ok(entries) = fs::read_dir(&artifacts) {
            let mut reports: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|ext| ext == "txt").unwrap_or(false))
                .map(|e| e.path())
                .collect();
            reports.sort_by_key(|p| p.metadata().unwrap().modified().unwrap());
            if let Some(last) = reports.last() {
                self.last_report_path = Some(last.clone());
                self.state = AppState::ViewLastReport;
            }
        }
        Ok(())
    }

    fn open_report(&mut self) -> Result<()> {
        if let Some(path) = &self.last_report_path {
            #[cfg(target_os = "macos")]
            std::process::Command::new("open").arg(path).spawn()?;
            #[cfg(target_os = "linux")]
            std::process::Command::new("xdg-open").arg(path).spawn()?;
            #[cfg(target_os = "windows")]
            std::process::Command::new("cmd").args(["/C", "start", ""]).arg(path).spawn()?;
        }
        Ok(())
    }

    fn open_report_dir(&mut self) -> Result<()> {
        if let Some(path) = &self.last_report_path {
            if let Some(parent) = path.parent() {
                #[cfg(target_os = "macos")]
                std::process::Command::new("open").arg(parent).spawn()?;
                #[cfg(target_os = "linux")]
                std::process::Command::new("xdg-open").arg(parent).spawn()?;
                #[cfg(target_os = "windows")]
                std::process::Command::new("cmd").args(["/C", "start", ""]).arg(parent).spawn()?;
            }
        }
        Ok(())
    }

    fn open_output_dir(&mut self) -> Result<()> {
        // Open the Desktop/Hyntel Reports folder (create if doesn't exist)
        let path = if let Some(desktop) = dirs::desktop_dir() {
            let hyntel_dir = desktop.join("Hyntel Reports");
            if !hyntel_dir.exists() {
                fs::create_dir_all(&hyntel_dir)?;
            }
            hyntel_dir
        } else {
            // Fallback to configured output dir
            let path = &self.config.output_dir;
            if !path.exists() {
                fs::create_dir_all(path)?;
            }
            path.clone()
        };

        #[cfg(target_os = "macos")]
        std::process::Command::new("open").arg(&path).spawn()?;
        #[cfg(target_os = "linux")]
        std::process::Command::new("xdg-open").arg(&path).spawn()?;
        #[cfg(target_os = "windows")]
        std::process::Command::new("cmd").args(["/C", "start", ""]).arg(&path).spawn()?;
        Ok(())
    }

    fn change_output_dir(&mut self) -> Result<()> {
        // Use native file picker (rfd crate would be ideal, but using OS commands for now)
        let path = if let Some(desktop) = dirs::desktop_dir() {
            let hyntel_dir = desktop.join("Hyntel Reports");
            if !hyntel_dir.exists() {
                fs::create_dir_all(&hyntel_dir)?;
            }
            hyntel_dir
        } else {
            self.config.output_dir.clone()
        };

        // Open native file picker
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!("set theDir to choose folder with prompt \"Select output directory\" default location \"{}\"", path.display()))
                .arg("-e")
                .arg("POSIX path of theDir")
                .output()?;
            if output.status.success() {
                let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !selected.is_empty() {
                    self.config.output_dir = PathBuf::from(selected);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("zenity")
                .args(["--file-selection", "--directory", "--title=Select output directory", &format!("--filename={}/", path.display())])
                .output()?;
            if output.status.success() {
                let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !selected.is_empty() {
                    self.config.output_dir = PathBuf::from(selected);
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let output = std::process::Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "-Command",
                    &format!("[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; $folder = New-Object System.Windows.Forms.FolderBrowserDialog; $folder.SelectedPath = '{}'; $folder.ShowDialog() | Out-Null; Write-Host $folder.SelectedPath", path.display()),
                ])
                .output()?;
            if output.status.success() {
                let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !selected.is_empty() && selected != "\r\n" {
                    self.config.output_dir = PathBuf::from(selected);
                }
            }
        }
        Ok(())
    }

    fn show_help(&self) -> Result<()> {
        // Could show a help modal
        Ok(())
    }

    fn run_audit(&mut self) -> Result<()> {
        let hours = match self.config.time_frame {
            TimeFrame::Custom => self.config.custom_hours,
            _ => self.config.time_frame.hours(),
        };

        let report = self.engine.run_audit(
            self.config.target_os.clone(),
            self.config.include_cves,
            3,
            self.config.generate_remediation,
            self.config.scan_apps,
            25,
            self.config.save_to_desktop,
            &self.config.output_dir,
            self.config.collect_logs,
            hours,
            self.config.scan_ad,
        )?;

        // Save report with new naming convention
        self.save_report_with_naming(&report)?;

        self.state = AppState::Results(report);
        Ok(())
    }

    fn save_report_with_naming(&mut self, report: &AuditReport) -> Result<()> {
        let now = chrono::Local::now();
        let date_str = now.format("%Y-%m-%d").to_string();
        let time_str = now.format("%I-%M-%S-%p").to_string(); // 02-30-45-PM
        let platform_str = platform_to_str(&report.target_platform);

        let base_name = format!("hyntel-{}-{}-{}", platform_str, date_str, time_str);
        let report_dir = self.config.output_dir.join(&base_name);
        fs::create_dir_all(&report_dir)?;

        let text_path = report_dir.join(format!("{}.txt", base_name));
        let json_path = report_dir.join(format!("{}.json", base_name));
        let csv_path = report_dir.join(format!("{}.csv", base_name));

        fs::write(&text_path, hyntel_core::reporting::render_text_report(report))?;
        fs::write(&json_path, hyntel_core::reporting::render_json_report(report)?)?;
        fs::write(&csv_path, hyntel_core::reporting::render_csv_report(report))?;

        if self.config.save_to_desktop {
            if let Some(desktop) = dirs::desktop_dir() {
                let desktop_dir = desktop.join("Hyntel Reports").join(&base_name);
                fs::create_dir_all(&desktop_dir)?;
                fs::copy(&text_path, desktop_dir.join(format!("{}.txt", base_name)))?;
                fs::copy(&json_path, desktop_dir.join(format!("{}.json", base_name)))?;
                fs::copy(&csv_path, desktop_dir.join(format!("{}.csv", base_name)))?;
            }
        }

        self.last_report_path = Some(text_path);
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
            match self.state {
                AppState::MainMenu => self.render_main_menu(frame),
                AppState::Configure => self.render_configure(frame),
                AppState::RunAudit => self.render_run_audit(frame),
                AppState::Running => self.render_running(frame),
                AppState::Results(ref report) => self.render_results(frame, report),
                AppState::ViewLastReport => self.render_view_last_report(frame),
                AppState::OutputLocation => self.render_output_location(frame),
                AppState::Error(ref err) => self.render_error(frame, err),
            }
        }

    fn render_main_menu(&self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(12),
                Constraint::Length(3),
            ])
            .split(area);

        // Title
        let title = Paragraph::new("HYNTEL - Security Audit Tool")
            .style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ORANGE)));
        frame.render_widget(title, chunks[0]);

        // Grid menu (2 columns x 3 rows)
        let menu_items = [
            ("Run Audit", "Configure and run security audit"),
            ("Configure", "Set scan options and preferences"),
            ("Last Report", "View most recent scan results"),
            ("Output Dir", "Manage output directory"),
            ("Help", "Show keyboard shortcuts"),
            ("Exit", "Quit application"),
        ];

        let grid_area = chunks[1];
        let _item_width = (grid_area.width as usize - 4) / 2;
        let item_height = (grid_area.height as usize - 2) / 3;

        let mut items = Vec::new();
        for (i, (label, desc)) in menu_items.iter().enumerate() {
            let _row = i / 2;
            let _col = i % 2;
            let selected = i == self.selected_main;
            items.push((i, *label, *desc, selected));
        }

        let item_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Length(item_height as u16); 3])
            .split(grid_area);

        for (row_idx, chunk) in item_chunks.iter().enumerate() {
            let row_items = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(*chunk);

            for col_idx in 0..2 {
                let idx = row_idx * 2 + col_idx;
                if idx < menu_items.len() {
                    let (_, label, desc, selected) = &items[idx];
                    let (fg, bg, border_color) = if *selected {
                        (Color::White, Color::Black, Color::White)
                    } else {
                        (Color::DarkGray, Color::Black, Color::White)
                    };

                    let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);

                    let text = vec![
                        Line::from(Span::styled(format!("  {}", label), style)),
                        Line::from(Span::styled(format!("  {}", desc), Style::default().fg(GRAY))),
                    ];

                    let block = Paragraph::new(text)
                        .style(style)
                        .alignment(Alignment::Left)
                        .block(Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(border_color)));

                    frame.render_widget(block, row_items[col_idx]);
                }
            }
        }

        // Footer
        let footer = Paragraph::new("←/→/↑/↓ Navigate  Enter Select  q/Quit")
            .style(Style::default().fg(GRAY))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[2]);
    }

    fn render_configure(&self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(15),
                Constraint::Length(3),
            ])
            .split(area);

        // Title - black/white frame
        let title = Paragraph::new("Configure Scan Options")
            .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
        frame.render_widget(title, chunks[0]);

        // Config options as grid
        let options = self.get_config_options();
        let grid_area = chunks[1];

        // Calculate grid layout
        let cols = 2;
        let rows = (options.len() + cols - 1) / cols;
        let row_constraints: Vec<Constraint> = (0..rows).map(|_| Constraint::Length(4)).collect();

        let row_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(row_constraints)
            .split(grid_area);

        for (row_idx, row_chunk) in row_chunks.iter().enumerate() {
            let col_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(*row_chunk);

            for col_idx in 0..cols {
                let idx = row_idx * cols + col_idx;
                if idx < options.len() {
                    let (label, value, selected) = &options[idx];
                    let (fg, bg, border_color) = if *selected {
                        (Color::White, Color::Black, Color::White)  // Inverse: white text on black bg
                    } else {
                        (Color::DarkGray, Color::Black, Color::White)  // Gray text, black bg, white border
                    };

                    let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);

                    let text = vec![
                        Line::from(Span::styled(format!(" {:<18} {}", label, value), style)),
                    ];

                    let block = Paragraph::new(text)
                        .style(style)
                        .alignment(Alignment::Left)
                        .block(Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(border_color)));

                    frame.render_widget(block, col_chunks[col_idx]);
                }
            }
        }

        // Footer
        let footer = Paragraph::new("←/→/↑/↓ Navigate  Enter Toggle  R Run Audit  q Back")
            .style(Style::default().fg(GRAY))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[2]);
    }

    fn get_config_options(&self) -> Vec<(String, String, bool)> {
        let target_os = match self.config.target_os {
            None => "Auto",
            Some(Platform::Linux) => "Linux",
            Some(Platform::MacOS) => "macOS",
            Some(Platform::Windows) => "Windows",
            Some(Platform::Unknown) => "Unknown",
        };

        let time_frame = match self.config.time_frame {
            TimeFrame::Hours24 => "24 hours",
            TimeFrame::Hours48 => "48 hours",
            TimeFrame::Hours72 => "72 hours",
            TimeFrame::Custom => "Custom",
        };

        let standards = if self.config.standards.is_empty() {
            "None".to_string()
        } else {
            self.config.standards.join(", ")
        };

        vec![
            ("Target OS".to_string(), target_os.to_string(), self.selected_config == 0),
            ("CVE Enrichment".to_string(), if self.config.include_cves { "ON" } else { "OFF" }.to_string(), self.selected_config == 1),
            ("Remediation Script".to_string(), if self.config.generate_remediation { "ON" } else { "OFF" }.to_string(), self.selected_config == 2),
            ("Scan Apps".to_string(), if self.config.scan_apps { "ON" } else { "OFF" }.to_string(), self.selected_config == 3),
            ("Save to Desktop".to_string(), if self.config.save_to_desktop { "ON" } else { "OFF" }.to_string(), self.selected_config == 4),
            ("Collect Logs".to_string(), if self.config.collect_logs { "ON" } else { "OFF" }.to_string(), self.selected_config == 5),
            ("Time Frame".to_string(), time_frame.to_string(), self.selected_config == 6),
            ("Custom Hours".to_string(), format!("{}h", self.config.custom_hours), self.selected_config == 7),
            ("AD Scan".to_string(), if self.config.scan_ad { "ON" } else { "OFF" }.to_string(), self.selected_config == 8),
            ("Standards".to_string(), standards, self.selected_config == 9),
            ("Output Dir".to_string(), "Change...".to_string(), self.selected_config == 10),
            ("Run Audit".to_string(), "Start".to_string(), self.selected_config == 11),
            ("Back".to_string(), "Return".to_string(), self.selected_config == 12),
        ]
    }

    fn render_run_audit(&self, frame: &mut Frame) {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(3),
                ])
                .split(area);

            let title = Paragraph::new("Running Security Audit")
                .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
            frame.render_widget(title, chunks[0]);

            let config = &self.config;
            let time_frame_str = match config.time_frame {
                TimeFrame::Custom => format!("{} hours (custom)", config.custom_hours),
                _ => config.time_frame.label().to_string(),
            };

            let standards_str = if config.standards.is_empty() { "All".to_string() } else { config.standards.join(", ") };
            let details = vec![
                Line::from(vec![Span::styled("Target OS: ", Style::default().fg(Color::White)), Span::raw(match &config.target_os { None => "Auto", Some(p) => platform_to_str(p) })]),
                Line::from(vec![Span::styled("CVE Enrichment: ", Style::default().fg(Color::White)), Span::raw(if config.include_cves { "Enabled" } else { "Disabled" })]),
                Line::from(vec![Span::styled("Remediation: ", Style::default().fg(Color::White)), Span::raw(if config.generate_remediation { "Enabled" } else { "Disabled" })]),
                Line::from(vec![Span::styled("Scan Apps: ", Style::default().fg(Color::White)), Span::raw(if config.scan_apps { "Enabled" } else { "Disabled" })]),
                Line::from(vec![Span::styled("Collect Logs: ", Style::default().fg(Color::White)), Span::raw(if config.collect_logs { format!("{} ({})", time_frame_str, if config.time_frame == TimeFrame::Custom { "custom" } else { "preset" }) } else { "Disabled".to_string() })]),
                Line::from(vec![Span::styled("AD Scan: ", Style::default().fg(Color::White)), Span::raw(if config.scan_ad { "Enabled" } else { "Disabled" })]),
                Line::from(vec![Span::styled("Standards: ", Style::default().fg(Color::White)), Span::raw(standards_str)]),
                Line::from(vec![Span::styled("Output Dir: ", Style::default().fg(Color::White)), Span::raw(config.output_dir.display().to_string())]),
            ];

            let paragraph = Paragraph::new(details)
                .style(Style::default().fg(Color::White))
                .alignment(Alignment::Left)
                .block(Block::default().borders(Borders::ALL).title("Configuration"))
                .wrap(Wrap { trim: true });
            frame.render_widget(paragraph, chunks[1]);

            let footer = Paragraph::new("Press Esc or Enter to cancel and return to menu")
                .style(Style::default().fg(GRAY))
                .alignment(Alignment::Center);
            frame.render_widget(footer, chunks[2]);
        }

    fn render_running(&self, frame: &mut Frame) {
        let area = frame.area();
        let paragraph = Paragraph::new("Running security audit...\n\nThis may take a moment.\n\nPress Esc to cancel and return to menu.")
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Scanning").border_style(Style::default().fg(Color::White)))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn render_results(&self, frame: &mut Frame, report: &AuditReport) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);

        let summary = hyntel_core::reporting::summarize_results(&report.results);
        let header_text = format!(
            "{} | {} passed  {} failed  {} skipped  |  {}",
            platform_to_str(&report.target_platform),
            summary.passed.to_string().green(),
            summary.failed.to_string().red(),
            summary.skipped.to_string().yellow(),
            if report.remediation_path.is_some() { "Remediation: ✓" } else { "" }
        );

        let header = Paragraph::new(header_text)
            .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
        frame.render_widget(header, chunks[0]);

        let items: Vec<ListItem> = report.results.iter().enumerate().map(|(i, (rule, result))| {
            let status_color = match result.status {
                hyntel_core::models::CheckStatus::Pass => Color::Green,
                hyntel_core::models::CheckStatus::Fail => Color::Red,
                hyntel_core::models::CheckStatus::Skip => Color::Yellow,
            };
            let status_str = match result.status {
                hyntel_core::models::CheckStatus::Pass => "✓ PASS",
                hyntel_core::models::CheckStatus::Fail => "✗ FAIL",
                hyntel_core::models::CheckStatus::Skip => "⊘ SKIP",
            };
            let style = if i == self.scroll_offset {
                Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", status_str), Style::default().fg(status_color)),
                Span::styled(&rule.title, style),
                Span::styled(format!(" ({:?})", rule.severity), Style::default().fg(GRAY)),
            ]))
        }).collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Results - ↑/↓ Scroll").border_style(Style::default().fg(Color::White)))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(list, chunks[1]);

        let footer = Paragraph::new("↑/↓ Scroll  PgUp/PgDn  Home/End  Enter/Esc Back  q Quit")
            .style(Style::default().fg(GRAY))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[2]);
    }

    fn render_view_last_report(&self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);

        let title = Paragraph::new("Last Scan Report")
            .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
        frame.render_widget(title, chunks[0]);

        let options = [
            ("Open Report", "Open the report in default viewer"),
            ("Open Folder", "Open containing folder"),
            ("Back", "Return to main menu"),
        ];

        let items: Vec<ListItem> = options.iter().enumerate().map(|(i, (label, desc))| {
            let (fg, bg, border_color) = if i == self.selected_report {
                (Color::White, Color::Black, Color::White)
            } else {
                (Color::DarkGray, Color::Black, Color::White)
            };

            let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);

            ListItem::new(Line::from(vec![
                Span::styled(format!("  {}: {}", label, desc), style),
            ]))
        }).collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Actions").border_style(Style::default().fg(Color::White)))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(list, chunks[1]);

        let footer = Paragraph::new("↑/↓ Navigate  Enter Select  Esc/q Back")
            .style(Style::default().fg(GRAY))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[2]);
    }

    fn render_output_location(&self, frame: &mut Frame) {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(3),
                ])
                .split(area);

            let title = Paragraph::new("Output Directory")
                .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
            frame.render_widget(title, chunks[0]);

            let options = [
                ("Open Folder", "Open output directory in file manager"),
                ("Change Path", "Set custom output directory"),
                ("Back", "Return to main menu"),
            ];

            let items: Vec<ListItem> = options.iter().enumerate().map(|(i, (label, desc))| {
                let (fg, bg, border_color) = if i == self.selected_output {
                    (Color::White, Color::Black, Color::White)
                } else {
                    (Color::DarkGray, Color::Black, Color::White)
                };

                let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);

                ListItem::new(Line::from(vec![
                    Span::styled(format!("  {}: {}", label, desc), style),
                ]))
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Actions").border_style(Style::default().fg(Color::White)));

            let output_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(10),
                ])
                .split(chunks[1]);

            let current = Paragraph::new(format!("Current: {}", self.config.output_dir.display()))
                .style(Style::default().fg(GRAY))
                .alignment(Alignment::Left);

            frame.render_widget(current, output_chunks[0]);
            frame.render_widget(list, output_chunks[1]);

            let footer = Paragraph::new("↑/↓ Navigate  Enter Select  Esc/q Back")
                .style(Style::default().fg(GRAY))
                .alignment(Alignment::Center);
            frame.render_widget(footer, chunks[2]);
        }

        fn render_error(&self, frame: &mut Frame, error: &str) {
            let area = frame.area();
            let paragraph = Paragraph::new(format!("Error: {}", error))
                .style(Style::default().fg(Color::Red))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Error").border_style(Style::default().fg(Color::White)))
                .wrap(Wrap { trim: true });
            frame.render_widget(paragraph, area);
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

pub fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new()?;
    let result = app.run(&mut terminal);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    result
}

fn main() -> Result<()> {
    run_tui()
}