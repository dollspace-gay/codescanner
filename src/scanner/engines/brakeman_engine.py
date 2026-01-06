import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class BrakemanEngine(BaseEngine):
    name = "brakeman"
    description = "Ruby on Rails security scanner"

    CONFIDENCE_MAP = {
        "High": "high",
        "Medium": "medium",
        "Weak": "low",
    }

    WARNING_TYPE_SEVERITY = {
        "SQL Injection": Severity.CRITICAL,
        "Command Injection": Severity.CRITICAL,
        "Remote Code Execution": Severity.CRITICAL,
        "Dangerous Eval": Severity.CRITICAL,
        "Cross-Site Scripting": Severity.HIGH,
        "Cross Site Scripting": Severity.HIGH,
        "Cross-Site Request Forgery": Severity.HIGH,
        "Session Setting": Severity.HIGH,
        "Authentication": Severity.HIGH,
        "Mass Assignment": Severity.HIGH,
        "Redirect": Severity.MEDIUM,
        "File Access": Severity.HIGH,
        "Dynamic Render Path": Severity.MEDIUM,
        "Denial of Service": Severity.HIGH,
        "Information Disclosure": Severity.MEDIUM,
        "Unscoped Find": Severity.MEDIUM,
        "Unsafe Deserialization": Severity.CRITICAL,
        "Default Routes": Severity.LOW,
        "Format Validation": Severity.LOW,
        "Dangerous Send": Severity.HIGH,
        "SSL Verification Bypass": Severity.HIGH,
    }

    CWE_MAP = {
        "SQL Injection": "CWE-89",
        "Command Injection": "CWE-78",
        "Remote Code Execution": "CWE-94",
        "Dangerous Eval": "CWE-95",
        "Cross-Site Scripting": "CWE-79",
        "Cross Site Scripting": "CWE-79",
        "Cross-Site Request Forgery": "CWE-352",
        "Session Setting": "CWE-384",
        "Authentication": "CWE-287",
        "Mass Assignment": "CWE-915",
        "Redirect": "CWE-601",
        "File Access": "CWE-22",
        "Dynamic Render Path": "CWE-22",
        "Denial of Service": "CWE-400",
        "Information Disclosure": "CWE-200",
        "Unscoped Find": "CWE-639",
        "Unsafe Deserialization": "CWE-502",
        "Dangerous Send": "CWE-94",
        "SSL Verification Bypass": "CWE-295",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("brakeman")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/brakeman",
            "/usr/local/bin/brakeman",
            "/opt/homebrew/bin/brakeman",
        ]
        for path in common_paths:
            if Path(path).exists():
                self._executable = path
                return path

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["brakeman.bat", "brakeman"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        return None

    def is_available(self) -> bool:
        exe = self._find_executable()
        if not exe:
            return False
        try:
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0 and "brakeman" in result.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _is_rails_project(self, target_path: Path) -> bool:
        rails_indicators = [
            target_path / "config" / "application.rb",
            target_path / "config" / "environment.rb",
            target_path / "Gemfile",
            target_path / "app" / "controllers",
            target_path / "config" / "routes.rb",
        ]

        rails_count = sum(1 for indicator in rails_indicators if indicator.exists())
        return rails_count >= 2

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        if not self._is_rails_project(target_path):
            self.log("No Rails project detected, skipping Brakeman")
            return []

        self.log(f"Running Brakeman security scan on Rails project at {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Brakeman executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "--format", "json",
                    "--quiet",
                    "--no-pager",
                    "--path", str(target_path),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Brakeman scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Brakeman error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Brakeman JSON output")
            return []

        warnings = data.get("warnings", [])

        for warning in warnings:
            warning_type = warning.get("warning_type", "Unknown")
            message = warning.get("message", "")
            confidence = warning.get("confidence", "Medium")
            file_path_str = warning.get("file", "")
            line = warning.get("line")
            code = warning.get("code", "")
            link = warning.get("link", "")
            check_name = warning.get("check_name", "")

            severity = self.WARNING_TYPE_SEVERITY.get(warning_type, Severity.MEDIUM)
            confidence_val = self.CONFIDENCE_MAP.get(confidence, "medium")
            cwe_id = self.CWE_MAP.get(warning_type)

            if file_path_str:
                file_path = target_path / file_path_str
            else:
                file_path = target_path

            description = message
            if code:
                description += f"\n\nCode:\n{code}"
            if link:
                description += f"\n\nMore info: {link}"

            finding = Finding(
                title=f"{warning_type}: {check_name}",
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line,
                cwe_id=cwe_id,
                tool=self.name,
                confidence=confidence_val,
                remediation=self._get_remediation(warning_type),
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} Rails security issues")
        return findings

    def _get_remediation(self, warning_type: str) -> str:
        remediations = {
            "SQL Injection": "Use parameterized queries or ActiveRecord's built-in escaping. Never interpolate user input into SQL strings.",
            "Command Injection": "Avoid system calls with user input. Use array form of system() or Open3 with proper escaping.",
            "Remote Code Execution": "Never evaluate user-controlled input. Use safe alternatives like JSON parsing instead of eval.",
            "Dangerous Eval": "Remove eval/instance_eval with user input. Use safe parsing methods or whitelisting.",
            "Cross-Site Scripting": "Use Rails' built-in escaping (html_escape). Mark user content as sanitized only when safe.",
            "Cross Site Scripting": "Use Rails' built-in escaping (html_escape). Mark user content as sanitized only when safe.",
            "Cross-Site Request Forgery": "Ensure protect_from_forgery is enabled. Use CSRF tokens in forms and AJAX requests.",
            "Session Setting": "Use secure session settings: httponly: true, secure: true, same_site: :strict.",
            "Authentication": "Implement proper authentication. Use established gems like Devise with secure configuration.",
            "Mass Assignment": "Use strong parameters. Whitelist allowed attributes with permit().",
            "Redirect": "Validate redirect URLs. Use only_path: true or whitelist allowed domains.",
            "File Access": "Validate file paths. Use File.basename and reject paths with '..' or absolute paths.",
            "Dynamic Render Path": "Whitelist allowed templates. Never render user-controlled paths directly.",
            "Denial of Service": "Add timeouts and limits. Use pagination and rate limiting for resource-intensive operations.",
            "Information Disclosure": "Remove sensitive data from responses. Use proper error handling that doesn't leak info.",
            "Unscoped Find": "Scope database queries to current user. Use current_user.posts.find() instead of Post.find().",
            "Unsafe Deserialization": "Never deserialize untrusted data with Marshal or YAML. Use JSON instead.",
            "Default Routes": "Remove default routes. Define explicit routes for all actions.",
            "Format Validation": "Validate format of user input (email, URL, etc.) using Rails validators.",
            "Dangerous Send": "Whitelist allowed methods when using send() with user input.",
            "SSL Verification Bypass": "Enable SSL verification. Remove verify_mode = OpenSSL::SSL::VERIFY_NONE.",
        }
        return remediations.get(
            warning_type,
            "Review Brakeman documentation at https://brakemanscanner.org/docs/"
        )
