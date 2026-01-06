import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class HorusecEngine(BaseEngine):
    name = "horusec"
    description = "Multi-language security analysis tool"

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "UNKNOWN": Severity.INFO,
    }

    CONFIDENCE_MAP = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }

    LANGUAGE_EXTENSIONS = {
        ".go": "Go",
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".java": "Java",
        ".kt": "Kotlin",
        ".cs": "C#",
        ".rb": "Ruby",
        ".php": "PHP",
        ".c": "C",
        ".cpp": "C++",
        ".swift": "Swift",
        ".dart": "Dart",
        ".ex": "Elixir",
        ".exs": "Elixir",
        ".erl": "Erlang",
        ".sh": "Shell",
        ".bash": "Shell",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".tf": "Terraform",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("horusec")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/horusec",
            "/usr/local/bin/horusec",
            "/opt/homebrew/bin/horusec",
        ]
        for path in common_paths:
            if Path(path).exists():
                self._executable = path
                return path

        return None

    def is_available(self) -> bool:
        exe = self._find_executable()
        if not exe:
            return False
        try:
            result = subprocess.run(
                [exe, "version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0 or "horusec" in result.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        self.log(f"Running Horusec security scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Horusec executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "start",
                    "-p", str(target_path),
                    "-o", "json",
                    "-O", "-",
                    "--disable-docker",
                    "-i", ".git,node_modules,vendor,__pycache__,.venv,venv",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Horusec scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Horusec error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            lines = output.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        data = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                self.log("Failed to parse Horusec JSON output")
                return []

        vulnerabilities = data.get("analysisVulnerabilities", [])
        if not vulnerabilities:
            vulnerabilities = data.get("vulnerabilities", [])

        for vuln_wrapper in vulnerabilities:
            vuln = vuln_wrapper.get("vulnerabilities", vuln_wrapper)
            if isinstance(vuln, list):
                for v in vuln:
                    finding = self._parse_vulnerability(v, target_path)
                    if finding:
                        findings.append(finding)
            else:
                finding = self._parse_vulnerability(vuln, target_path)
                if finding:
                    findings.append(finding)

        self.log(f"Found {len(findings)} security issues")
        return findings

    def _parse_vulnerability(self, vuln: dict, target_path: Path) -> Optional[Finding]:
        severity_str = vuln.get("severity", "MEDIUM")
        confidence_str = vuln.get("confidence", "MEDIUM")
        details = vuln.get("details", "")
        file_path_str = vuln.get("file", "")
        line = vuln.get("line", "")
        code = vuln.get("code", "")
        rule_id = vuln.get("securityTool", "")
        vuln_type = vuln.get("type", "")
        language = vuln.get("language", "")
        vuln_hash = vuln.get("vulnHash", "")

        severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
        confidence = self.CONFIDENCE_MAP.get(confidence_str.upper(), "medium")

        cwe_id = self._extract_cwe(details)

        if file_path_str:
            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = target_path / file_path_str
        else:
            file_path = target_path

        try:
            line_num = int(line.split("-")[0]) if line else None
        except (ValueError, AttributeError):
            line_num = None

        description = details
        if code:
            description += f"\n\nCode:\n{code}"
        if language:
            description += f"\n\nLanguage: {language}"

        title = vuln_type if vuln_type else "Security Issue"
        if rule_id:
            title = f"[{rule_id}] {title}"

        return Finding(
            title=title,
            description=description,
            severity=severity,
            file_path=file_path,
            line_number=line_num,
            cwe_id=cwe_id,
            tool=self.name,
            confidence=confidence,
            remediation=self._get_remediation(vuln_type, details),
        )

    def _extract_cwe(self, details: str) -> Optional[str]:
        import re
        cwe_pattern = r'CWE-(\d+)'
        match = re.search(cwe_pattern, details, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return None

    def _get_remediation(self, vuln_type: str, details: str) -> str:
        vuln_lower = vuln_type.lower() if vuln_type else ""
        details_lower = details.lower()

        if "sql" in vuln_lower or "sql" in details_lower:
            return "Use parameterized queries or prepared statements to prevent SQL injection."
        elif "xss" in vuln_lower or "cross-site scripting" in details_lower:
            return "Encode or escape user input before rendering in HTML. Use framework-provided escaping."
        elif "injection" in vuln_lower:
            return "Validate and sanitize all user input. Use safe APIs that don't interpret input as code."
        elif "hardcoded" in vuln_lower or "hard-coded" in details_lower:
            return "Remove hardcoded credentials. Use environment variables or a secrets manager."
        elif "crypto" in vuln_lower or "encryption" in details_lower:
            return "Use modern cryptographic algorithms (AES-256, SHA-256+). Avoid MD5, SHA1, DES."
        elif "path traversal" in details_lower or "directory" in details_lower:
            return "Validate file paths. Use canonical paths and restrict to allowed directories."
        elif "deserialization" in details_lower:
            return "Avoid deserializing untrusted data. Use safe formats like JSON instead."
        elif "csrf" in vuln_lower or "cross-site request" in details_lower:
            return "Implement CSRF tokens for state-changing operations."
        elif "ssl" in details_lower or "tls" in details_lower or "certificate" in details_lower:
            return "Enable proper SSL/TLS verification. Don't disable certificate validation."
        elif "random" in details_lower:
            return "Use cryptographically secure random number generators for security-sensitive operations."
        elif "password" in details_lower:
            return "Use strong password hashing (bcrypt, Argon2). Never store passwords in plain text."
        else:
            return "Review the security issue and apply appropriate remediation based on the vulnerability type."
