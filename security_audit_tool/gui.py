from __future__ import annotations

import queue
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox
from urllib.error import HTTPError, URLError

from .cli import _attach_cves
from .cleanup import cleanup_all, cleanup_desktop_reports, cleanup_memory_state
from .inventory import assess_processes, inventory_applications, inventory_running_processes, map_applications_to_cves
from .models import CheckResult, DriverInfo, ProcessFinding, RunningProcess
from .reporting import export_report_bundle
from .remediation import write_remediation_script
from .system_checks import detect_os_info, detect_platform, get_windows_drivers, run_audit


RETRO_BG = "#1f2427"
RETRO_PANEL = "#262c30"
RETRO_TEXT = "#f4f6f8"
RETRO_MUTED = "#b7c0c8"
RETRO_WARN = "#ffd166"
RETRO_FAIL = "#ff7a7a"
RETRO_BORDER = "#5d6972"


@dataclass(frozen=True)
class AuditConfig:
    target_os_mode: str
    standard_key: str
    include_cves: bool
    generate_remediation: bool
    scan_apps: bool
    save_reports: bool
    remediation_dir: Path
    report_dir: Path


def standards_for_selection(selected: str) -> list[str] | None:
    mapping = {
        "general": None,
        "pci": ["PCI_DSS"],
        "hipaa": ["HIPAA"],
        "iso": ["ISO27001"],
    }
    return mapping[selected]


class SecurityAuditGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Security Audit Terminal")
        self.root.geometry("980x700")
        self.root.configure(bg=RETRO_BG)
        self.root.tk_setPalette(
            background=RETRO_BG,
            foreground=RETRO_TEXT,
            activeBackground="#2f363b",
            activeForeground=RETRO_TEXT,
            selectBackground="#2478d4",
            selectForeground="#ffffff",
        )
        self.root.minsize(860, 620)

        self.result_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.current_results: list[tuple] = []
        self.current_target_os: str | None = None
        self.current_remediation_path: Path | None = None
        self.current_application_findings = None
        self.current_applications: list = []
        self.current_drivers: list[DriverInfo] = []
        self.current_processes: list[RunningProcess] = []
        self.current_process_findings: list[ProcessFinding] = []
        self.current_os_info = None
        self.current_export_paths: dict[str, Path] = {}
        self.current_report_dir = Path.home() / "Desktop" / "Hyntel Report"

        self.target_os_var = tk.StringVar(value="auto")
        self.standard_var = tk.StringVar(value="general")
        self.include_cves_var = tk.BooleanVar(value=False)
        self.generate_remediation_var = tk.BooleanVar(value=True)
        self.scan_apps_var = tk.BooleanVar(value=False)
        self.save_reports_var = tk.BooleanVar(value=True)
        self.remediation_dir_var = tk.StringVar(value=str(Path.cwd() / "artifacts"))
        self.report_dir_var = tk.StringVar(value=str(self.current_report_dir))
        self.status_var = tk.StringVar(value="READY")
        self.export_var = tk.StringVar(value="Desktop export: pending")
        self.output_buffer = ""

        self._configure_style()
        self._build_layout()
        self.root.after(150, self._poll_queue)

    def _configure_style(self) -> None:
        self.label_options = {
            "bg": RETRO_BG,
            "fg": RETRO_TEXT,
            "font": ("Menlo", 11),
        }
        self.panel_label_options = {
            "bg": RETRO_PANEL,
            "fg": RETRO_TEXT,
            "font": ("Menlo", 12, "bold"),
        }

    def _make_canvas_label(
        self,
        parent: tk.Misc,
        text: str,
        *,
        bg: str = RETRO_BG,
        fg: str = RETRO_TEXT,
        font: tuple[str, int] | tuple[str, int, str] = ("Menlo", 11),
        height: int = 24,
        anchor: str = "w",
    ) -> tk.Canvas:
        canvas = tk.Canvas(parent, height=height, bg=bg, highlightthickness=0, borderwidth=0)
        x = 0 if anchor == "w" else 8
        canvas.create_text(x, height // 2, text=text, fill=fg, font=font, anchor=anchor)
        return canvas

    def _make_panel(self, parent: tk.Misc, **grid_options) -> tk.Frame:
        wrapper = tk.Frame(parent, bg=RETRO_BORDER, padx=1, pady=1)
        inner = tk.Frame(wrapper, bg=RETRO_PANEL, padx=14, pady=14)
        inner.pack(fill="both", expand=True)
        wrapper.grid(**grid_options)
        return inner

    def _make_button(self, parent: tk.Misc, text: str, command) -> tk.Button:
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=RETRO_PANEL,
            fg=RETRO_TEXT,
            activebackground="#1a271d",
            activeforeground="#ffffff",
            font=("Menlo", 10, "bold"),
            padx=12,
            pady=7,
            borderwidth=1,
            relief="solid",
            highlightthickness=1,
            highlightbackground=RETRO_MUTED,
            highlightcolor=RETRO_TEXT,
        )
        button.bind("<Enter>", lambda _event: button.configure(bg="#1a271d"))
        button.bind("<Leave>", lambda _event: button.configure(bg=RETRO_PANEL))
        return button

    def _make_choice(self, parent: tk.Misc, text: str, variable, value, kind: str) -> tk.Widget:
        widget_class = tk.Checkbutton if kind == "check" else tk.Radiobutton
        options = {
            "text": text,
            "variable": variable,
            "bg": RETRO_PANEL,
            "fg": RETRO_TEXT,
            "activebackground": RETRO_PANEL,
            "activeforeground": RETRO_TEXT,
            "selectcolor": RETRO_PANEL,
            "font": ("Menlo", 10),
            "borderwidth": 0,
            "highlightthickness": 0,
            "anchor": "w",
        }
        if kind == "check":
            return widget_class(parent, **options)
        return widget_class(parent, value=value, **options)

    def _build_layout(self) -> None:
        outer = tk.Frame(self.root, bg=RETRO_BG, padx=18, pady=18)
        outer.pack(fill="both", expand=True)

        header = self._make_canvas_label(
            outer,
            "SECURITY AUDIT TERMINAL",
            font=("Menlo", 18, "bold"),
            height=34,
        )
        header.pack(fill="x")

        subtitle = self._make_canvas_label(
            outer,
            "Cross-platform security configuration scanning with Desktop report export",
            fg=RETRO_MUTED,
            font=("Menlo", 11),
            height=24,
        )
        subtitle.pack(fill="x", pady=(4, 14))

        control_wrapper = tk.Frame(outer, bg=RETRO_BORDER, padx=1, pady=1)
        control_wrapper.pack(fill="x")
        control_panel = tk.Frame(control_wrapper, bg=RETRO_PANEL, padx=14, pady=14)
        control_panel.pack(fill="x")

        self._make_canvas_label(control_panel, "TARGET OS", bg=RETRO_PANEL, font=("Menlo", 12, "bold")).grid(row=0, column=0, sticky="ew")
        for idx, option in enumerate(("auto", "linux", "macos", "windows")):
            self._make_choice(control_panel, option.upper(), self.target_os_var, option, "radio").grid(
                row=1, column=idx, sticky="w", padx=(0, 18), pady=(8, 10)
            )

        self._make_canvas_label(control_panel, "SCAN TYPE", bg=RETRO_PANEL, font=("Menlo", 12, "bold")).grid(row=2, column=0, sticky="ew", pady=(4, 0))
        scan_options = (
            ("GENERAL", "general"),
            ("PCI DSS", "pci"),
            ("HIPAA", "hipaa"),
            ("ISO 27001", "iso"),
        )
        for idx, (label, value) in enumerate(scan_options):
            self._make_choice(control_panel, label, self.standard_var, value, "radio").grid(
                row=3, column=idx, sticky="w", padx=(0, 18), pady=(8, 10)
            )

        self._make_choice(control_panel, "INCLUDE NVD CVE LOOKUP", self.include_cves_var, True, "check").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=4
        )
        self._make_choice(control_panel, "GENERATE REMEDIATION SCRIPT", self.generate_remediation_var, True, "check").grid(
            row=4, column=2, columnspan=2, sticky="w", pady=4
        )
        self._make_choice(control_panel, "SCAN INSTALLED APPS AND PROCESSES", self.scan_apps_var, True, "check").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=4
        )
        self._make_choice(control_panel, "EXPORT AUDIT REPORTS", self.save_reports_var, True, "check").grid(
            row=5, column=2, columnspan=2, sticky="w", pady=4
        )

        self._make_canvas_label(control_panel, "REMEDIATION DIRECTORY", bg=RETRO_PANEL, font=("Menlo", 12, "bold")).grid(row=6, column=0, sticky="ew", pady=(14, 4))
        remediation_entry = tk.Entry(
            control_panel,
            textvariable=self.remediation_dir_var,
            width=50,
            bg=RETRO_BG,
            fg=RETRO_TEXT,
            insertbackground=RETRO_TEXT,
            relief="flat",
            font=("Menlo", 10),
            highlightthickness=1,
            highlightbackground=RETRO_MUTED,
            highlightcolor=RETRO_TEXT,
        )
        remediation_entry.grid(row=7, column=0, columnspan=2, sticky="ew", padx=(0, 12), pady=(0, 8))

        self._make_canvas_label(control_panel, "REPORT DIRECTORY", bg=RETRO_PANEL, font=("Menlo", 12, "bold")).grid(row=6, column=2, sticky="ew", pady=(14, 4))
        report_entry = tk.Entry(
            control_panel,
            textvariable=self.report_dir_var,
            width=50,
            bg=RETRO_BG,
            fg=RETRO_TEXT,
            insertbackground=RETRO_TEXT,
            relief="flat",
            font=("Menlo", 10),
            highlightthickness=1,
            highlightbackground=RETRO_MUTED,
            highlightcolor=RETRO_TEXT,
        )
        report_entry.grid(row=7, column=2, columnspan=2, sticky="ew", padx=(0, 10), pady=(0, 8))

        button_row = tk.Frame(control_panel, bg=RETRO_PANEL)
        button_row.grid(row=8, column=0, columnspan=4, sticky="w", pady=(14, 4))
        self._make_button(button_row, "RUN AUDIT", self._start_audit).pack(side="left", padx=(0, 10))
        self._make_button(button_row, "SAVE REPORTS AGAIN", self._save_reports_again).pack(side="left", padx=(0, 10))
        self._make_button(button_row, "CLEAN UP", self._cleanup).pack(side="left")
        for column in range(4):
            control_panel.grid_columnconfigure(column, weight=1)

        info_bar = tk.Frame(outer, bg=RETRO_BG)
        info_bar.pack(fill="x", pady=(14, 10))
        self.status_canvas = self._make_canvas_label(info_bar, self.status_var.get(), font=("Menlo", 11, "bold"), height=24)
        self.status_canvas.pack(side="left", fill="x", expand=True)
        self.export_canvas = self._make_canvas_label(info_bar, self.export_var.get(), fg=RETRO_MUTED, height=24)
        self.export_canvas.pack(side="right", fill="x", expand=True)

        output_frame = tk.Frame(outer, bg=RETRO_BORDER, padx=1, pady=1)
        output_frame.pack(fill="both", expand=True)
        output_inner = tk.Frame(output_frame, bg=RETRO_BG)
        output_inner.pack(fill="both", expand=True)
        self.output_canvas = tk.Canvas(output_inner, bg=RETRO_BG, highlightthickness=0, borderwidth=0)
        self.output_scrollbar = tk.Scrollbar(output_inner, orient="vertical", command=self.output_canvas.yview)
        self.output_canvas.configure(yscrollcommand=self.output_scrollbar.set)
        self.output_scrollbar.pack(side="right", fill="y")
        self.output_canvas.pack(side="left", fill="both", expand=True)
        self.output_text_item = self.output_canvas.create_text(
            12,
            12,
            text="",
            fill=RETRO_TEXT,
            font=("Menlo", 11),
            anchor="nw",
            width=900,
        )
        self.output_canvas.bind("<Configure>", self._resize_output_text)

        self._append_output("BOOT> GUI initialized.\nBOOT> Press RUN AUDIT to start a scan.\n")

    def _append_output(self, text: str, tag: str | None = None) -> None:
        self.output_buffer += text
        self.output_canvas.itemconfigure(self.output_text_item, text=self.output_buffer)
        self._sync_output_scroll()

    def _resize_output_text(self, event: tk.Event) -> None:
        self.output_canvas.itemconfigure(self.output_text_item, width=max(100, event.width - 28))
        self._sync_output_scroll()

    def _sync_output_scroll(self) -> None:
        bbox = self.output_canvas.bbox(self.output_text_item)
        if bbox:
            self.output_canvas.configure(scrollregion=(0, 0, bbox[2] + 12, bbox[3] + 12))
            self.output_canvas.yview_moveto(1.0)
        self.output_canvas.update_idletasks()

    def _set_status(self, value: str) -> None:
        self.status_var.set(value)
        if hasattr(self, "status_canvas"):
            self.status_canvas.itemconfigure(1, text=value)

    def _set_export(self, value: str) -> None:
        self.export_var.set(value)
        if hasattr(self, "export_canvas"):
            self.export_canvas.itemconfigure(1, text=value)

    def _start_audit(self) -> None:
        try:
            config = AuditConfig(
                target_os_mode=self.target_os_var.get(),
                standard_key=self.standard_var.get(),
                include_cves=self.include_cves_var.get(),
                generate_remediation=self.generate_remediation_var.get(),
                scan_apps=self.scan_apps_var.get(),
                save_reports=self.save_reports_var.get(),
                remediation_dir=Path(self.remediation_dir_var.get()).expanduser(),
                report_dir=Path(self.report_dir_var.get()).expanduser(),
            )
        except OSError as exc:
            messagebox.showerror("Security Audit Terminal", f"Invalid path: {exc}")
            return

        self._set_status("RUNNING")
        self._set_export("Report export: pending" if config.save_reports else "Report export: disabled")
        self.output_buffer = ""
        self.output_canvas.itemconfigure(self.output_text_item, text="")
        self._append_output("BOOT> Starting security audit...\n")
        self._append_output(f"BOOT> Target OS mode: {config.target_os_mode}\n")
        self._append_output(f"BOOT> Scan type: {config.standard_key}\n")
        self._append_output(f"BOOT> Include CVEs: {config.include_cves}\n")
        self._append_output(f"BOOT> Generate remediation: {config.generate_remediation}\n")
        self._append_output(f"BOOT> Scan installed apps and processes: {config.scan_apps}\n")
        self._append_output(f"BOOT> Export reports: {config.save_reports}\n\n")

        worker = threading.Thread(target=self._run_audit_worker, args=(config,), daemon=True)
        worker.start()

    def _run_audit_worker(self, config: AuditConfig) -> None:
        try:
            target_os = detect_platform() if config.target_os_mode == "auto" else config.target_os_mode
            if target_os == "unknown":
                raise RuntimeError("Could not detect a supported platform.")

            # Detect OS info
            try:
                os_info = detect_os_info()
                self.result_queue.put(("os_info", os_info))
            except Exception:
                os_info = None

            standards = standards_for_selection(config.standard_key)
            results = run_audit(target_os, standards=standards)
            if config.include_cves:
                self.result_queue.put(("log", "NET> Querying related CVEs from NIST NVD where applicable...\n"))
                _attach_cves(results, 3)

            applications: list = []
            application_findings = None
            processes: list[RunningProcess] = []
            process_findings: list[ProcessFinding] = []
            if config.scan_apps:
                self.result_queue.put(("log", "INV> Inventorying installed applications...\n"))
                applications = inventory_applications(target_os, limit=25)
                self.result_queue.put(("log", f"INV> Found {len(applications)} application(s). Matching against NVD CVEs...\n"))
                try:
                    application_findings = map_applications_to_cves(applications)
                except (HTTPError, URLError, TimeoutError, OSError) as exc:
                    application_findings = []
                    self.result_queue.put(("log", f"INV> Application CVE lookup unavailable: {exc}\n"))
                self.result_queue.put(("log", "PROC> Reviewing running processes for suspicious indicators...\n"))
                processes = inventory_running_processes(target_os, limit=100)
                process_findings = assess_processes(processes)

            # Windows driver signing
            drivers: list[DriverInfo] = []
            if target_os == "windows":
                self.result_queue.put(("log", "DRV> Querying Windows driver signing information...\n"))
                from .system_checks import CommandRunner
                try:
                    drivers = get_windows_drivers(CommandRunner())
                    self.result_queue.put(("log", f"DRV> Retrieved signing info for {len(drivers)} driver(s).\n"))
                except Exception as exc:
                    self.result_queue.put(("log", f"DRV> Driver query failed: {exc}\n"))

            failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
            remediation_path = None
            if config.generate_remediation and failed_results:
                remediation_path = write_remediation_script(config.remediation_dir, target_os, failed_results)
                self.result_queue.put(("log", f"FIX> Remediation script generated at {remediation_path}\n"))

            exports: dict[str, Path] = {}
            if config.save_reports:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                export_base = config.report_dir / timestamp
                exports = export_report_bundle(
                    target_os, results, remediation_path, application_findings,
                    desktop_base=export_base,
                    scanned_applications=applications or None,
                    os_info=os_info,
                    scanned_processes=processes or None,
                    process_findings=process_findings,
                )
            self.result_queue.put(("done", (target_os, results, remediation_path, applications, application_findings, processes, process_findings, drivers, os_info, exports)))
        except Exception as exc:  # pragma: no cover - GUI fallback path
            self.result_queue.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                if kind == "log":
                    self._append_output(str(payload))
                elif kind == "os_info":
                    info = payload
                    self._append_output("\n── SYSTEM INFORMATION ──────────────────────────────\n", "header")
                    self._append_output(f"  OS      : {info.name}\n")
                    self._append_output(f"  Version : {info.version}\n")
                    if info.architecture:
                        self._append_output(f"  Arch    : {info.architecture}\n")
                    if info.build:
                        self._append_output(f"  Build   : {info.build}\n")
                    if info.kernel:
                        self._append_output(f"  Kernel  : {info.kernel}\n")
                    if info.security_patches:
                        self._append_output(f"  Security patches ({len(info.security_patches)} installed):\n")
                        for kb in info.security_patches[:10]:
                            self._append_output(f"    {kb}\n", "muted")
                        if len(info.security_patches) > 10:
                            self._append_output(f"    ... and {len(info.security_patches) - 10} more\n", "muted")
                    self._append_output("\n")
                elif kind == "error":
                    self._set_status("ERROR")
                    self._append_output(f"ERR> {payload}\n", "fail")
                    messagebox.showerror("Security Audit Terminal", str(payload))
                elif kind == "done":
                    target_os, results, remediation_path, applications, application_findings, processes, process_findings, drivers, os_info, exports = payload
                    self.current_target_os = target_os
                    self.current_results = results
                    self.current_remediation_path = remediation_path
                    self.current_applications = applications
                    self.current_application_findings = application_findings
                    self.current_processes = processes
                    self.current_process_findings = process_findings
                    self.current_drivers = drivers
                    self.current_os_info = os_info
                    self.current_export_paths = exports
                    self._set_status("COMPLETE")
                    if exports:
                        self._set_export(f"Report export: {exports['text_report'].parent}")
                    else:
                        self._set_export("Report export: skipped")
                    self._append_output("\nSYS> Audit complete.\n\n", "header")
                    self._render_results(target_os, results, remediation_path, applications, application_findings, processes, process_findings, drivers)
                    if exports:
                        self._append_output("\nEXPORT> Saved report bundle.\n")
                        self._append_output(f"EXPORT> {exports['text_report']}\n", "muted")
                        self._append_output(f"EXPORT> {exports['json_report']}\n", "muted")
                        self._append_output(f"EXPORT> {exports['csv_report']}\n", "muted")
                    else:
                        self._append_output("\nEXPORT> Report export skipped.\n", "muted")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _render_results(
        self,
        target_os: str,
        results: list[tuple],
        remediation_path: Path | None,
        applications: list,
        application_findings,
        processes: list[RunningProcess],
        process_findings: list[ProcessFinding],
        drivers: list[DriverInfo],
    ) -> None:
        self._append_output("── AUDIT RESULTS ───────────────────────────────────\n", "header")
        for rule, result in results:
            status = result.status.upper()
            tag = {"PASS": "pass", "FAIL": "fail", "WARN": "warn", "SKIP": "skip"}.get(status, None)
            icon = {"PASS": "✔", "FAIL": "✘", "WARN": "⚠", "SKIP": "–"}.get(status, "?")
            self._append_output(f"  {icon} [{status}] {rule.title}  [{rule.severity.upper()}]\n", tag)
            self._append_output(f"    What we checked: {rule.description}\n", "muted")
            self._append_output(f"    Why it matters : {rule.rationale}\n", "muted")
            if result.details:
                self._append_output(f"    ↳ {result.details}\n", "muted")
            if result.observed_value:
                self._append_output(f"    ↳ Observed: {result.observed_value}\n", "muted")
            if result.remediation:
                self._append_output("    Recommended action:\n", "muted")
                for action in result.remediation[:3]:
                    self._append_output(f"      • {action}\n", "muted")
            if result.related_cves:
                for cve in result.related_cves[:3]:
                    cve_id = cve.get("id") or "N/A"
                    severity = cve.get("severity") or "?"
                    score = cve.get("score")
                    score_str = f", score {score}" if score is not None else ""
                    self._append_output(f"      • {cve_id} ({severity}{score_str})\n", "warn")

        passed = sum(1 for _, r in results if r.status == "pass")
        failed = sum(1 for _, r in results if r.status == "fail")
        skipped = sum(1 for _, r in results if r.status == "skip")
        self._append_output(f"\n  Summary: {passed} passed | {failed} failed | {skipped} skipped\n")

        # Application scan results
        if applications:
            self._append_output(f"\n── INSTALLED APPLICATIONS ({len(applications)} scanned) ─────────\n", "header")
            for app in applications:
                self._append_output(f"  {app.name:<35} {app.version:<20} ({app.source})\n", "muted")
            if application_findings:
                self._append_output(f"\n  ⚠ CVE matches found for {len(application_findings)} app(s):\n", "warn")
                for finding in application_findings:
                    app = finding.application
                    self._append_output(f"  • {app.name} {app.version}\n", "fail")
                    for cve in finding.cves[:3]:
                        cve_id = cve.get("id") or "N/A"
                        severity = cve.get("severity") or "?"
                        score = cve.get("score")
                        score_str = f", score {score}" if score is not None else ""
                        self._append_output(f"      {cve_id} ({severity}{score_str})\n", "warn")
            elif application_findings is not None:
                self._append_output("  ✔ No CVE matches found for scanned applications.\n", "pass")
            self._append_output(f"\n── RUNNING PROCESSES ({len(processes)} reviewed) ───────────────\n", "header")
            if process_findings:
                for finding in process_findings[:15]:
                    self._append_output(f"  [{finding.severity.upper()}] PID {finding.process.pid} {finding.process.name}\n", "warn")
                    for reason in finding.reasons:
                        self._append_output(f"    Why flagged: {reason}\n", "muted")
                    if finding.process.executable:
                        self._append_output(f"    Executable : {finding.process.executable}\n", "muted")
                    if finding.recommended_action:
                        self._append_output(f"    Action     : {finding.recommended_action}\n", "muted")
            else:
                self._append_output("  ✔ No obviously suspicious running processes were detected.\n", "pass")

        # Windows driver signing
        if drivers:
            dangerous = [d for d in drivers if d.is_dangerous]
            suspicious = [d for d in drivers if d.is_suspicious and not d.is_dangerous]
            self._append_output(f"\n── DRIVER SIGNATURES ({len(drivers)} drivers) ────────────────\n", "header")
            microsoft_count = sum(1 for d in drivers if d.sign_type == "microsoft")
            custom_count = sum(1 for d in drivers if d.sign_type == "custom")
            self._append_output(f"  Microsoft-signed: {microsoft_count}  |  Custom-signed: {custom_count}  |  Unsigned: {len(dangerous)}\n")
            if suspicious:
                self._append_output(f"\n  ⚠ SUSPICIOUS (custom-signed) — {len(suspicious)} driver(s):\n", "warn")
                for d in suspicious[:20]:
                    self._append_output(f"    → {d.name}  (Signer: {d.signer or 'unknown'})\n", "warn")
                if len(suspicious) > 20:
                    self._append_output(f"    ... and {len(suspicious) - 20} more\n", "muted")
            if dangerous:
                self._append_output(f"\n  ⛔ DANGEROUS (unsigned) — {len(dangerous)} driver(s):\n", "danger")
                for d in dangerous[:20]:
                    self._append_output(f"    → {d.name}  Provider: {d.provider or 'N/A'}\n", "danger")
                if len(dangerous) > 20:
                    self._append_output(f"    ... and {len(dangerous) - 20} more\n", "muted")
            if not suspicious and not dangerous:
                self._append_output("  ✔ All drivers are Microsoft/WHQL-signed.\n", "pass")

    def _save_reports_again(self) -> None:
        if not self.current_results or not self.current_target_os:
            messagebox.showinfo("Security Audit Terminal", "Run an audit before exporting reports.")
            return
        exports = export_report_bundle(
            self.current_target_os,
            self.current_results,
            self.current_remediation_path,
            self.current_application_findings,
            desktop_base=Path(self.report_dir_var.get()).expanduser() / datetime.now().strftime("%Y%m%d_%H%M%S"),
            scanned_applications=self.current_applications or None,
            os_info=self.current_os_info,
            scanned_processes=self.current_processes or None,
            process_findings=self.current_process_findings,
        )
        self.current_export_paths = exports
        self._set_export(f"Report export: {exports['text_report'].parent}")
        self._append_output("\nEXPORT> Saved another report bundle.\n")
        self._append_output(f"EXPORT> {exports['text_report']}\n", "muted")
        self._append_output(f"EXPORT> {exports['json_report']}\n", "muted")
        self._append_output(f"EXPORT> {exports['csv_report']}\n", "muted")

    def _cleanup(self) -> None:
        """Clean up audit artifacts, Desktop reports, and clear in-memory state."""
        if not messagebox.askyesno(
            "Security Audit Terminal",
            "This will securely delete all audit artifacts, Desktop reports, "
            "and clear the current scan results from memory.\n\n"
            "The virtual environment will NOT be removed.\n\n"
            "Continue?",
        ):
            return

        self._set_status("CLEANING")
        self._append_output("\nCLEAN> Starting cleanup...\n")

        # Clear in-memory scan state first
        mem_result = cleanup_memory_state(self)
        if mem_result.get("memory_state"):
            self._append_output("CLEAN> In-memory scan state cleared.\n")
        else:
            self._append_output("CLEAN> WARNING: Failed to clear some in-memory state.\n", "fail")

        # Clean artifacts and Desktop reports (not venv)
        cleanup_result = cleanup_all(include_venv=False)
        for section, outcome in cleanup_result.items():
            for key, ok in outcome.items():
                status = "removed" if ok else "FAILED"
                icon = "✔" if ok else "✘"
                self._append_output(f"CLEAN> {icon} {key}: {status}\n", "pass" if ok else "fail")

        self._set_status("CLEANED")
        self._append_output("\nCLEAN> Cleanup complete.\n")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    app = SecurityAuditGUI()
    app.run()
    return 0
