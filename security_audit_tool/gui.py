from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .cli import _attach_cves
from .inventory import assess_processes, inventory_applications, inventory_running_processes, map_applications_to_cves
from .models import CheckResult, DriverInfo, ProcessFinding, RunningProcess
from .reporting import export_report_bundle
from .remediation import write_remediation_script
from .system_checks import detect_os_info, detect_platform, get_windows_drivers, run_audit


RETRO_BG = "#0b120d"
RETRO_PANEL = "#111a13"
RETRO_TEXT = "#8cff72"
RETRO_MUTED = "#4f7a52"
RETRO_WARN = "#ffd166"
RETRO_FAIL = "#ff6b6b"


class SecurityAuditGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Security Audit Terminal")
        self.root.geometry("980x700")
        self.root.configure(bg=RETRO_BG)
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

        self.target_os_var = tk.StringVar(value="auto")
        self.include_cves_var = tk.BooleanVar(value=False)
        self.generate_remediation_var = tk.BooleanVar(value=True)
        self.scan_apps_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="READY")
        self.export_var = tk.StringVar(value="Desktop export: pending")

        self._configure_style()
        self._build_layout()
        self.root.after(150, self._poll_queue)

    def _configure_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Retro.TFrame", background=RETRO_BG)
        style.configure("Panel.TFrame", background=RETRO_PANEL, borderwidth=1, relief="solid")
        style.configure("Retro.TLabel", background=RETRO_BG, foreground=RETRO_TEXT, font=("Courier", 11))
        style.configure("Header.TLabel", background=RETRO_BG, foreground=RETRO_TEXT, font=("Courier", 18, "bold"))
        style.configure("PanelTitle.TLabel", background=RETRO_PANEL, foreground=RETRO_TEXT, font=("Courier", 12, "bold"))
        style.configure(
            "Retro.TButton",
            background=RETRO_PANEL,
            foreground=RETRO_TEXT,
            font=("Courier", 10, "bold"),
            padding=8,
        )
        style.map("Retro.TButton", background=[("active", "#1a271d")], foreground=[("disabled", RETRO_MUTED)])
        style.configure(
            "Retro.TRadiobutton",
            background=RETRO_BG,
            foreground=RETRO_TEXT,
            font=("Courier", 10),
        )
        style.map("Retro.TRadiobutton", background=[("active", RETRO_BG)])
        style.configure(
            "Retro.TCheckbutton",
            background=RETRO_BG,
            foreground=RETRO_TEXT,
            font=("Courier", 10),
        )
        style.map("Retro.TCheckbutton", background=[("active", RETRO_BG)])

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, style="Retro.TFrame", padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Label(outer, text="SECURITY AUDIT TERMINAL", style="Header.TLabel")
        header.pack(anchor="w")

        subtitle = ttk.Label(
            outer,
            text="Cross-platform security configuration scanning with Desktop report export",
            style="Retro.TLabel",
        )
        subtitle.pack(anchor="w", pady=(4, 14))

        control_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        control_panel.pack(fill="x")

        ttk.Label(control_panel, text="TARGET OS", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        for idx, option in enumerate(("auto", "linux", "macos", "windows")):
            ttk.Radiobutton(
                control_panel,
                text=option.upper(),
                value=option,
                variable=self.target_os_var,
                style="Retro.TRadiobutton",
            ).grid(row=1, column=idx, sticky="w", padx=(0, 14), pady=(8, 8))

        ttk.Checkbutton(
            control_panel,
            text="INCLUDE NVD CVE LOOKUP",
            variable=self.include_cves_var,
            style="Retro.TCheckbutton",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=4)

        ttk.Checkbutton(
            control_panel,
            text="GENERATE REMEDIATION SCRIPT",
            variable=self.generate_remediation_var,
            style="Retro.TCheckbutton",
        ).grid(row=2, column=2, columnspan=2, sticky="w", pady=4)
        ttk.Checkbutton(
            control_panel,
            text="SCAN INSTALLED APPS FOR CVES",
            variable=self.scan_apps_var,
            style="Retro.TCheckbutton",
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=4)

        button_row = ttk.Frame(control_panel, style="Panel.TFrame", padding=0)
        button_row.grid(row=4, column=0, columnspan=4, sticky="w", pady=(14, 4))
        ttk.Button(button_row, text="RUN AUDIT", style="Retro.TButton", command=self._start_audit).pack(side="left", padx=(0, 10))
        ttk.Button(button_row, text="SAVE REPORTS AGAIN", style="Retro.TButton", command=self._save_reports_again).pack(side="left")

        info_bar = ttk.Frame(outer, style="Retro.TFrame")
        info_bar.pack(fill="x", pady=(14, 10))
        ttk.Label(info_bar, textvariable=self.status_var, style="Retro.TLabel").pack(side="left")
        ttk.Label(info_bar, textvariable=self.export_var, style="Retro.TLabel").pack(side="right")

        self.output = scrolledtext.ScrolledText(
            outer,
            wrap=tk.WORD,
            bg=RETRO_BG,
            fg=RETRO_TEXT,
            insertbackground=RETRO_TEXT,
            selectbackground="#24452a",
            selectforeground=RETRO_TEXT,
            font=("Courier", 11),
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=12,
        )
        self.output.pack(fill="both", expand=True)

        # Configure colour tags for the text widget
        self.output.tag_configure("pass", foreground="#8cff72")
        self.output.tag_configure("fail", foreground="#ff6b6b")
        self.output.tag_configure("warn", foreground="#ffd166")
        self.output.tag_configure("skip", foreground="#4f7a52")
        self.output.tag_configure("header", foreground="#8cff72", font=("Courier", 11, "bold"))
        self.output.tag_configure("muted", foreground="#4f7a52")
        self.output.tag_configure("danger", foreground="#ff6b6b", font=("Courier", 11, "bold"))

        self._append_output("BOOT> GUI initialized.\nBOOT> Press RUN AUDIT to start a scan.\n")

    def _append_output(self, text: str, tag: str | None = None) -> None:
        if tag:
            self.output.insert(tk.END, text, tag)
        else:
            self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _start_audit(self) -> None:
        self.status_var.set("RUNNING")
        self.export_var.set("Desktop export: pending")
        self.output.delete("1.0", tk.END)
        self._append_output("BOOT> Starting security audit...\n")
        self._append_output(f"BOOT> Target OS mode: {self.target_os_var.get()}\n")
        self._append_output(f"BOOT> Include CVEs: {self.include_cves_var.get()}\n")
        self._append_output(f"BOOT> Generate remediation: {self.generate_remediation_var.get()}\n")
        self._append_output(f"BOOT> Scan installed apps: {self.scan_apps_var.get()}\n\n")

        worker = threading.Thread(target=self._run_audit_worker, daemon=True)
        worker.start()

    def _run_audit_worker(self) -> None:
        try:
            target_os = detect_platform() if self.target_os_var.get() == "auto" else self.target_os_var.get()
            if target_os == "unknown":
                raise RuntimeError("Could not detect a supported platform.")

            # Detect OS info
            try:
                os_info = detect_os_info()
                self.result_queue.put(("os_info", os_info))
            except Exception:
                os_info = None

            results = run_audit(target_os)
            if self.include_cves_var.get():
                self.result_queue.put(("log", "NET> Querying related CVEs from NIST NVD where applicable...\n"))
                _attach_cves(results, 3)

            applications: list = []
            application_findings = None
            processes: list[RunningProcess] = []
            process_findings: list[ProcessFinding] = []
            if self.scan_apps_var.get():
                self.result_queue.put(("log", "INV> Inventorying installed applications...\n"))
                applications = inventory_applications(target_os, limit=25)
                self.result_queue.put(("log", f"INV> Found {len(applications)} application(s). Matching against NVD CVEs...\n"))
                application_findings = map_applications_to_cves(applications)
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
            if self.generate_remediation_var.get() and failed_results:
                remediation_path = write_remediation_script(Path("artifacts"), target_os, failed_results)
                self.result_queue.put(("log", f"FIX> Remediation script generated at {remediation_path}\n"))

            exports = export_report_bundle(
                target_os, results, remediation_path, application_findings,
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
                    self.status_var.set("ERROR")
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
                    self.status_var.set("COMPLETE")
                    self.export_var.set(f"Desktop export: {exports['text_report'].parent}")
                    self._append_output("\nSYS> Audit complete.\n\n", "header")
                    self._render_results(target_os, results, remediation_path, applications, application_findings, processes, process_findings, drivers)
                    self._append_output("\nEXPORT> Saved text report to Desktop.\n")
                    self._append_output(f"EXPORT> {exports['text_report']}\n", "muted")
                    self._append_output(f"EXPORT> {exports['json_report']}\n", "muted")
                    self._append_output(f"EXPORT> {exports['csv_report']}\n", "muted")
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
            scanned_applications=self.current_applications or None,
            os_info=self.current_os_info,
            scanned_processes=self.current_processes or None,
            process_findings=self.current_process_findings,
        )
        self.current_export_paths = exports
        self.export_var.set(f"Desktop export: {exports['text_report'].parent}")
        self._append_output("\nEXPORT> Saved another report bundle to Desktop.\n")
        self._append_output(f"EXPORT> {exports['text_report']}\n", "muted")
        self._append_output(f"EXPORT> {exports['json_report']}\n", "muted")
        self._append_output(f"EXPORT> {exports['csv_report']}\n", "muted")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    app = SecurityAuditGUI()
    app.run()
    return 0
