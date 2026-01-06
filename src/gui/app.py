import asyncio
import os
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from ..scanner import Scanner, ScanResult, Severity
from ..scanner.report import ReportGenerator
from ..scanner.engines.gemini_engine import GeminiEngine


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class EngineCategory(ctk.CTkFrame):
    """Collapsible category frame for organizing scanner engines."""

    def __init__(self, parent, title: str, icon: str = "▶", **kwargs):
        super().__init__(parent, **kwargs)
        self._expanded = True
        self._title = title
        self._icon = icon

        self.grid_columnconfigure(0, weight=1)

        self._header = ctk.CTkButton(
            self,
            text=f"▼ {icon} {title}",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="transparent",
            hover_color=("gray80", "gray25"),
            anchor="w",
            command=self._toggle,
        )
        self._header.grid(row=0, column=0, sticky="ew", padx=2, pady=2)

        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.grid(row=1, column=0, sticky="ew", padx=(15, 0))

        self._checkboxes: list[ctk.CTkCheckBox] = []

    def add_engine(self, text: str, variable: ctk.BooleanVar) -> ctk.CTkCheckBox:
        cb = ctk.CTkCheckBox(
            self._content,
            text=text,
            variable=variable,
            font=ctk.CTkFont(size=11),
        )
        cb.pack(anchor="w", pady=1)
        self._checkboxes.append(cb)
        return cb

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        if self._expanded:
            self._content.grid(row=1, column=0, sticky="ew", padx=(15, 0))
            self._header.configure(text=f"▼ {self._icon} {self._title}")
        else:
            self._content.grid_forget()
            self._header.configure(text=f"▶ {self._icon} {self._title}")

    def select_all(self) -> None:
        for cb in self._checkboxes:
            cb.select()

    def deselect_all(self) -> None:
        for cb in self._checkboxes:
            cb.deselect()


class CodeScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CodeScanner - Vulnerability Scanner")
        self.geometry("1200x800")
        self.minsize(900, 600)

        self._scan_result: Optional[ScanResult] = None
        self._is_scanning = False
        self._engine_categories: list[EngineCategory] = []

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._setup_sidebar()
        self._setup_main_area()

    def _setup_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(7, weight=1)

        logo_label = ctk.CTkLabel(
            sidebar,
            text="🔒 CodeScanner",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 5))

        subtitle = ctk.CTkLabel(
            sidebar,
            text="Security Vulnerability Scanner",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 20))

        dir_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        dir_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkLabel(dir_frame, text="Target Directory:").pack(anchor="w")

        self.dir_entry = ctk.CTkEntry(dir_frame, width=200)
        self.dir_entry.pack(side="left", fill="x", expand=True, pady=5)

        browse_btn = ctk.CTkButton(
            dir_frame, text="📁", width=40, command=self._browse_directory
        )
        browse_btn.pack(side="right", padx=(5, 0), pady=5)

        engines_header = ctk.CTkFrame(sidebar, fg_color="transparent")
        engines_header.grid(row=3, column=0, padx=20, pady=(15, 5), sticky="ew")

        ctk.CTkLabel(
            engines_header, text="Scanner Engines:", font=ctk.CTkFont(weight="bold")
        ).pack(side="left")

        select_btns = ctk.CTkFrame(engines_header, fg_color="transparent")
        select_btns.pack(side="right")
        ctk.CTkButton(
            select_btns, text="All", width=35, height=20,
            font=ctk.CTkFont(size=10), command=self._select_all_engines
        ).pack(side="left", padx=2)
        ctk.CTkButton(
            select_btns, text="None", width=35, height=20,
            font=ctk.CTkFont(size=10), command=self._deselect_all_engines
        ).pack(side="left")

        self.bandit_var = ctk.BooleanVar(value=True)
        self.semgrep_var = ctk.BooleanVar(value=True)
        self.safety_var = ctk.BooleanVar(value=True)
        self.gemini_var = ctk.BooleanVar(value=True)
        self.gitleaks_var = ctk.BooleanVar(value=True)
        self.trufflehog_var = ctk.BooleanVar(value=True)
        self.detect_secrets_var = ctk.BooleanVar(value=True)
        self.trivy_var = ctk.BooleanVar(value=True)
        self.grype_var = ctk.BooleanVar(value=True)
        self.checkov_var = ctk.BooleanVar(value=True)
        self.shellcheck_var = ctk.BooleanVar(value=True)
        self.hadolint_var = ctk.BooleanVar(value=True)
        self.gosec_var = ctk.BooleanVar(value=True)
        self.brakeman_var = ctk.BooleanVar(value=True)
        self.spotbugs_var = ctk.BooleanVar(value=True)
        self.phpstan_var = ctk.BooleanVar(value=True)
        self.horusec_var = ctk.BooleanVar(value=True)

        engines_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        engines_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        # SAST Category
        sast_cat = EngineCategory(engines_frame, "SAST", icon="🔍")
        sast_cat.pack(fill="x", pady=2)
        sast_cat.add_engine("Bandit (Python)", self.bandit_var)
        sast_cat.add_engine("Semgrep (Multi-lang)", self.semgrep_var)
        sast_cat.add_engine("ShellCheck (Shell)", self.shellcheck_var)
        sast_cat.add_engine("Gosec (Go)", self.gosec_var)
        sast_cat.add_engine("Brakeman (Rails)", self.brakeman_var)
        sast_cat.add_engine("SpotBugs (Java)", self.spotbugs_var)
        sast_cat.add_engine("PHPStan (PHP)", self.phpstan_var)
        sast_cat.add_engine("Horusec (Multi-lang)", self.horusec_var)
        self._engine_categories.append(sast_cat)

        # Secrets Detection Category
        secrets_cat = EngineCategory(engines_frame, "Secrets", icon="🔑")
        secrets_cat.pack(fill="x", pady=2)
        secrets_cat.add_engine("Gitleaks", self.gitleaks_var)
        secrets_cat.add_engine("TruffleHog", self.trufflehog_var)
        secrets_cat.add_engine("detect-secrets", self.detect_secrets_var)
        self._engine_categories.append(secrets_cat)

        # Dependencies Category
        deps_cat = EngineCategory(engines_frame, "Dependencies", icon="📦")
        deps_cat.pack(fill="x", pady=2)
        deps_cat.add_engine("Safety (Python)", self.safety_var)
        deps_cat.add_engine("Grype (Multi-lang)", self.grype_var)
        deps_cat.add_engine("Trivy (Vuln Scanner)", self.trivy_var)
        self._engine_categories.append(deps_cat)

        # IaC Category
        iac_cat = EngineCategory(engines_frame, "Infrastructure", icon="🏗️")
        iac_cat.pack(fill="x", pady=2)
        iac_cat.add_engine("Checkov (IaC)", self.checkov_var)
        iac_cat.add_engine("Hadolint (Docker)", self.hadolint_var)
        self._engine_categories.append(iac_cat)

        # AI Category
        ai_cat = EngineCategory(engines_frame, "AI Analysis", icon="🤖")
        ai_cat.pack(fill="x", pady=2)
        ai_cat.add_engine("Gemini AI", self.gemini_var)
        self._engine_categories.append(ai_cat)

        api_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        api_frame.grid(row=5, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkLabel(api_frame, text="Gemini API Key:").pack(anchor="w")
        self.api_key_entry = ctk.CTkEntry(api_frame, show="•", width=220)
        self.api_key_entry.pack(fill="x", pady=5)

        ctk.CTkLabel(api_frame, text="Gemini Model:").pack(anchor="w", pady=(10, 0))
        self.model_selector = ctk.CTkComboBox(
            api_frame,
            values=list(GeminiEngine.AVAILABLE_MODELS.keys()),
            width=220,
        )
        self.model_selector.set(GeminiEngine.DEFAULT_MODEL)
        self.model_selector.pack(fill="x", pady=5)

        self.scan_btn = ctk.CTkButton(
            sidebar,
            text="🔍 Start Scan",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            command=self._start_scan,
        )
        self.scan_btn.grid(row=6, column=0, padx=20, pady=15, sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(sidebar)
        self.progress_bar.grid(row=8, column=0, padx=20, pady=10, sticky="ew")
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            sidebar, text="Ready", text_color="gray", font=ctk.CTkFont(size=11)
        )
        self.status_label.grid(row=9, column=0, padx=20, pady=(0, 20))

    def _setup_main_area(self) -> None:
        main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)

        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.grid(row=0, column=0, sticky="nsew", rowspan=2)

        self.tabview.add("📋 Log")
        self.tabview.add("🔍 Findings")
        self.tabview.add("📊 Summary")

        self._setup_log_tab()
        self._setup_findings_tab()
        self._setup_summary_tab()

        export_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        export_frame.grid(row=2, column=0, sticky="ew", pady=10)

        ctk.CTkButton(
            export_frame, text="📄 Export Markdown", command=self._export_markdown
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            export_frame, text="🌐 Export HTML", command=self._export_html
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            export_frame, text="📦 Export JSON", command=self._export_json
        ).pack(side="left", padx=5)

    def _setup_log_tab(self) -> None:
        tab = self.tabview.tab("📋 Log")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        self.log_text = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    def _setup_findings_tab(self) -> None:
        tab = self.tabview.tab("🔍 Findings")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        filter_frame = ctk.CTkFrame(tab, fg_color="transparent")
        filter_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ctk.CTkLabel(filter_frame, text="Filter by severity:").pack(side="left")

        self.severity_filter = ctk.CTkComboBox(
            filter_frame,
            values=["All", "Critical", "High", "Medium", "Low", "Info"],
            command=self._filter_findings,
        )
        self.severity_filter.pack(side="left", padx=10)
        self.severity_filter.set("All")

        self.findings_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.findings_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    def _setup_summary_tab(self) -> None:
        tab = self.tabview.tab("📊 Summary")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        self.summary_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.summary_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    def _browse_directory(self) -> None:
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            self.dir_entry.delete(0, "end")
            self.dir_entry.insert(0, directory)

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")

    def _start_scan(self) -> None:
        if self._is_scanning:
            return

        target_path = self.dir_entry.get().strip()
        if not target_path:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return

        if not Path(target_path).is_dir():
            messagebox.showerror("Error", "Invalid directory path.")
            return

        api_key = self.api_key_entry.get().strip()
        if self.gemini_var.get() and not api_key:
            messagebox.showwarning(
                "Warning",
                "Gemini API key not provided. AI scanning will be disabled.",
            )
            self.gemini_var.set(False)

        self._is_scanning = True
        self.scan_btn.configure(state="disabled", text="⏳ Scanning...")
        self.progress_bar.set(0)
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        self.log_text.delete("1.0", "end")
        self.findings_text.delete("1.0", "end")
        self.summary_text.delete("1.0", "end")

        selected_model = self.model_selector.get()

        thread = threading.Thread(
            target=self._run_scan,
            args=(target_path, api_key, selected_model),
            daemon=True,
        )
        thread.start()

    def _run_scan(self, target_path: str, api_key: str, gemini_model: str) -> None:
        def on_progress(message: str) -> None:
            self.after(0, lambda: self._log(message))
            self.after(0, lambda: self.status_label.configure(text=message[:50]))

        scanner = Scanner(
            on_progress=on_progress,
            gemini_api_key=api_key if api_key else None,
            gemini_model=gemini_model,
            enable_bandit=self.bandit_var.get(),
            enable_semgrep=self.semgrep_var.get(),
            enable_safety=self.safety_var.get(),
            enable_gemini=self.gemini_var.get() and bool(api_key),
            enable_gitleaks=self.gitleaks_var.get(),
            enable_trufflehog=self.trufflehog_var.get(),
            enable_detect_secrets=self.detect_secrets_var.get(),
            enable_trivy=self.trivy_var.get(),
            enable_grype=self.grype_var.get(),
            enable_checkov=self.checkov_var.get(),
            enable_shellcheck=self.shellcheck_var.get(),
            enable_hadolint=self.hadolint_var.get(),
            enable_gosec=self.gosec_var.get(),
            enable_brakeman=self.brakeman_var.get(),
            enable_spotbugs=self.spotbugs_var.get(),
            enable_phpstan=self.phpstan_var.get(),
            enable_horusec=self.horusec_var.get(),
        )

        try:
            result = asyncio.run(scanner.scan(Path(target_path)))
            self.after(0, lambda: self._on_scan_complete(result))
        except Exception as e:
            self.after(0, lambda: self._on_scan_error(str(e)))

    def _on_scan_complete(self, result: ScanResult) -> None:
        self._scan_result = result
        self._is_scanning = False

        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1.0)
        self.scan_btn.configure(state="normal", text="🔍 Start Scan")

        total = len(result.findings)
        self.status_label.configure(text=f"Complete: {total} findings")
        self._log(f"\n{'='*50}")
        self._log(f"Scan complete! Found {total} potential vulnerabilities.")
        self._log(f"  Critical: {result.critical_count}")
        self._log(f"  High: {result.high_count}")
        self._log(f"  Medium: {result.medium_count}")
        self._log(f"  Low: {result.low_count}")
        self._log(f"  Info: {result.info_count}")

        if result.errors:
            self._log(f"\nErrors encountered: {len(result.errors)}")
            for error in result.errors:
                self._log(f"  - {error}")

        self._display_findings()
        self._display_summary()

        self.tabview.set("🔍 Findings")

    def _on_scan_error(self, error: str) -> None:
        self._is_scanning = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.scan_btn.configure(state="normal", text="🔍 Start Scan")
        self.status_label.configure(text="Error")
        self._log(f"\nERROR: {error}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error}")

    def _display_findings(self, severity_filter: Optional[str] = None) -> None:
        if not self._scan_result:
            return

        self.findings_text.delete("1.0", "end")

        findings = self._scan_result.findings
        if severity_filter and severity_filter != "All":
            severity_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
                "Info": Severity.INFO,
            }
            target_severity = severity_map.get(severity_filter)
            if target_severity:
                findings = [f for f in findings if f.severity == target_severity]

        if not findings:
            self.findings_text.insert("end", "No findings match the current filter.\n")
            return

        for i, finding in enumerate(findings, 1):
            severity_icons = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🟢",
                Severity.INFO: "⚪",
            }
            icon = severity_icons.get(finding.severity, "⚪")

            self.findings_text.insert("end", f"\n{'─'*60}\n")
            self.findings_text.insert(
                "end", f"{icon} [{finding.severity.value.upper()}] {finding.title}\n"
            )
            self.findings_text.insert("end", f"   File: {finding.file_path}\n")
            if finding.line_number:
                self.findings_text.insert("end", f"   Line: {finding.line_number}\n")
            self.findings_text.insert("end", f"   Tool: {finding.tool}\n")
            if finding.cwe_id:
                self.findings_text.insert("end", f"   CWE: {finding.cwe_id}\n")
            self.findings_text.insert("end", f"\n   {finding.description}\n")
            if finding.remediation:
                self.findings_text.insert("end", f"\n   💡 Remediation: {finding.remediation}\n")

    def _filter_findings(self, value: str) -> None:
        self._display_findings(value)

    def _display_summary(self) -> None:
        if not self._scan_result:
            return

        report = ReportGenerator(self._scan_result)
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("end", report.generate_markdown())

    def _export_markdown(self) -> None:
        if not self._scan_result:
            messagebox.showwarning("Warning", "No scan results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        )
        if file_path:
            report = ReportGenerator(self._scan_result)
            Path(file_path).write_text(report.generate_markdown(), encoding="utf-8")
            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")

    def _export_html(self) -> None:
        if not self._scan_result:
            messagebox.showwarning("Warning", "No scan results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        )
        if file_path:
            report = ReportGenerator(self._scan_result)
            Path(file_path).write_text(report.generate_html(), encoding="utf-8")
            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")
            if messagebox.askyesno("Open Report", "Open the report in your browser?"):
                webbrowser.open(f"file://{file_path}")

    def _export_json(self) -> None:
        if not self._scan_result:
            messagebox.showwarning("Warning", "No scan results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if file_path:
            Path(file_path).write_text(self._scan_result.to_json(), encoding="utf-8")
            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")

    def _load_settings(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if api_key:
            self.api_key_entry.insert(0, api_key)

    def _select_all_engines(self) -> None:
        for cat in self._engine_categories:
            cat.select_all()

    def _deselect_all_engines(self) -> None:
        for cat in self._engine_categories:
            cat.deselect_all()


def main() -> None:
    app = CodeScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
