from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .cli import _attach_cves
from .models import CheckResult
from .reporting import export_report_bundle, render_text_report
from .remediation import write_remediation_script
from .system_checks import detect_platform, run_audit


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
        self.current_export_paths: dict[str, Path] = {}

        self.target_os_var = tk.StringVar(value="auto")
        self.include_cves_var = tk.BooleanVar(value=False)
        self.generate_remediation_var = tk.BooleanVar(value=True)
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

        button_row = ttk.Frame(control_panel, style="Panel.TFrame", padding=0)
        button_row.grid(row=3, column=0, columnspan=4, sticky="w", pady=(14, 4))
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
        self._append_output("BOOT> GUI initialized.\nBOOT> Press RUN AUDIT to start a scan.\n")

    def _append_output(self, text: str) -> None:
        self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _start_audit(self) -> None:
        self.status_var.set("RUNNING")
        self.export_var.set("Desktop export: pending")
        self.output.delete("1.0", tk.END)
        self._append_output("BOOT> Starting security audit...\n")
        self._append_output(f"BOOT> Target OS mode: {self.target_os_var.get()}\n")
        self._append_output(f"BOOT> Include CVEs: {self.include_cves_var.get()}\n")
        self._append_output(f"BOOT> Generate remediation: {self.generate_remediation_var.get()}\n\n")

        worker = threading.Thread(target=self._run_audit_worker, daemon=True)
        worker.start()

    def _run_audit_worker(self) -> None:
        try:
            target_os = detect_platform() if self.target_os_var.get() == "auto" else self.target_os_var.get()
            if target_os == "unknown":
                raise RuntimeError("Could not detect a supported platform.")

            results = run_audit(target_os)
            if self.include_cves_var.get():
                self.result_queue.put(("log", "NET> Querying related CVEs from NIST NVD where applicable...\n"))
                _attach_cves(results, 3)

            failed_results: list[CheckResult] = [result for _, result in results if result.status == "fail"]
            remediation_path = None
            if self.generate_remediation_var.get() and failed_results:
                remediation_path = write_remediation_script(Path("artifacts"), target_os, failed_results)
                self.result_queue.put(("log", f"FIX> Remediation script generated at {remediation_path}\n"))

            exports = export_report_bundle(target_os, results, remediation_path)
            self.result_queue.put(("done", (target_os, results, remediation_path, exports)))
        except Exception as exc:  # pragma: no cover - GUI fallback path
            self.result_queue.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                if kind == "log":
                    self._append_output(str(payload))
                elif kind == "error":
                    self.status_var.set("ERROR")
                    self._append_output(f"ERR> {payload}\n")
                    messagebox.showerror("Security Audit Terminal", str(payload))
                elif kind == "done":
                    target_os, results, remediation_path, exports = payload
                    self.current_target_os = target_os
                    self.current_results = results
                    self.current_remediation_path = remediation_path
                    self.current_export_paths = exports
                    self.status_var.set("COMPLETE")
                    self.export_var.set(f"Desktop export: {exports['text_report'].parent}")
                    self._append_output("SYS> Audit complete.\n\n")
                    self._append_output(render_text_report(target_os, results, remediation_path))
                    self._append_output("\nEXPORT> Saved text report to Desktop.\n")
                    self._append_output(f"EXPORT> {exports['text_report']}\n")
                    self._append_output(f"EXPORT> {exports['json_report']}\n")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _save_reports_again(self) -> None:
        if not self.current_results or not self.current_target_os:
            messagebox.showinfo("Security Audit Terminal", "Run an audit before exporting reports.")
            return
        exports = export_report_bundle(self.current_target_os, self.current_results, self.current_remediation_path)
        self.current_export_paths = exports
        self.export_var.set(f"Desktop export: {exports['text_report'].parent}")
        self._append_output("\nEXPORT> Saved another report bundle to Desktop.\n")
        self._append_output(f"EXPORT> {exports['text_report']}\n")
        self._append_output(f"EXPORT> {exports['json_report']}\n")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    app = SecurityAuditGUI()
    app.run()
    return 0
