import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class BanditEngine(BaseEngine):
    name = "bandit"
    description = "Python security linter"

    SEVERITY_MAP = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    CONFIDENCE_MAP = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("bandit")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["bandit.exe", "bandit"]:
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
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def get_supported_extensions(self) -> set[str]:
        return {".py"}

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        python_files = [f for f in files if f.suffix == ".py"]
        if not python_files:
            self.log("No Python files to scan")
            return []

        self.log(f"Scanning {len(python_files)} Python files")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as file_list:
            for f in python_files:
                file_list.write(f"{f}\n")
            file_list_path = file_list.name

        try:
            exe = self._find_executable()
            if not exe:
                self.log("Bandit executable not found")
                return []

            result = subprocess.run(
                [
                    exe,
                    "-f", "json",
                    "-ll",
                    "--targets-from", file_list_path,
                ],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(target_path),
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Bandit scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Bandit error: {e}")
            return []
        finally:
            Path(file_list_path).unlink(missing_ok=True)

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Bandit output")
            return []

        for result in data.get("results", []):
            severity = self.SEVERITY_MAP.get(
                result.get("issue_severity", "LOW"), Severity.LOW
            )
            confidence = self.CONFIDENCE_MAP.get(
                result.get("issue_confidence", "LOW"), "low"
            )

            file_path = Path(result.get("filename", ""))
            if not file_path.is_absolute():
                file_path = target_path / file_path

            finding = Finding(
                title=result.get("test_name", "Unknown Issue"),
                description=result.get("issue_text", ""),
                severity=severity,
                file_path=file_path,
                line_number=result.get("line_number"),
                end_line=result.get("end_col_offset"),
                code_snippet=result.get("code", ""),
                cwe_id=self._get_cwe(result.get("test_id", "")),
                tool=self.name,
                confidence=confidence,
                remediation=self._get_remediation(result.get("test_id", "")),
            )
            findings.append(finding)

        return findings

    def _get_cwe(self, test_id: str) -> Optional[str]:
        cwe_map = {
            "B101": "CWE-703",
            "B102": "CWE-78",
            "B103": "CWE-732",
            "B104": "CWE-200",
            "B105": "CWE-259",
            "B106": "CWE-259",
            "B107": "CWE-259",
            "B108": "CWE-377",
            "B110": "CWE-703",
            "B112": "CWE-703",
            "B201": "CWE-94",
            "B301": "CWE-502",
            "B302": "CWE-611",
            "B303": "CWE-327",
            "B304": "CWE-327",
            "B305": "CWE-327",
            "B306": "CWE-377",
            "B307": "CWE-78",
            "B308": "CWE-79",
            "B309": "CWE-295",
            "B310": "CWE-22",
            "B311": "CWE-330",
            "B312": "CWE-295",
            "B313": "CWE-611",
            "B314": "CWE-611",
            "B315": "CWE-611",
            "B316": "CWE-611",
            "B317": "CWE-611",
            "B318": "CWE-611",
            "B319": "CWE-611",
            "B320": "CWE-611",
            "B321": "CWE-295",
            "B323": "CWE-295",
            "B324": "CWE-327",
            "B501": "CWE-295",
            "B502": "CWE-295",
            "B503": "CWE-295",
            "B504": "CWE-295",
            "B505": "CWE-327",
            "B506": "CWE-295",
            "B507": "CWE-295",
            "B601": "CWE-78",
            "B602": "CWE-78",
            "B603": "CWE-78",
            "B604": "CWE-78",
            "B605": "CWE-78",
            "B606": "CWE-78",
            "B607": "CWE-78",
            "B608": "CWE-89",
            "B609": "CWE-78",
            "B610": "CWE-78",
            "B611": "CWE-78",
            "B701": "CWE-94",
            "B702": "CWE-79",
            "B703": "CWE-79",
        }
        return cwe_map.get(test_id)

    def _get_remediation(self, test_id: str) -> str:
        remediation_map = {
            "B101": "Remove assert statements used for security checks; use proper validation instead.",
            "B102": "Avoid exec(); use safer alternatives like ast.literal_eval() for data parsing.",
            "B103": "Set restrictive file permissions (e.g., 0o600) when creating files.",
            "B104": "Avoid binding to all interfaces (0.0.0.0); bind to specific addresses.",
            "B105": "Remove hardcoded passwords; use environment variables or secret management.",
            "B106": "Remove hardcoded passwords from function arguments.",
            "B107": "Remove hardcoded passwords from default function arguments.",
            "B108": "Use tempfile module for temporary files instead of hardcoded /tmp paths.",
            "B110": "Handle exceptions explicitly; avoid bare 'except:' or 'except Exception:'.",
            "B112": "Avoid using 'continue' in exception handlers without logging.",
            "B201": "Avoid flask app.run() with debug=True in production.",
            "B301": "Avoid pickle for untrusted data; use JSON or other safe formats.",
            "B302": "Avoid marshal module; use JSON or other safe serialization.",
            "B303": "Use modern cryptographic algorithms (SHA-256+); avoid MD5/SHA1.",
            "B304": "Use modern ciphers; avoid DES and other weak algorithms.",
            "B305": "Use modern ciphers; avoid weak cipher modes.",
            "B306": "Use tempfile.mkstemp() instead of tempfile.mktemp().",
            "B307": "Avoid eval(); use ast.literal_eval() for safe evaluation.",
            "B308": "Use markupsafe.Markup for safe HTML; avoid mark_safe().",
            "B309": "Verify SSL certificates in HTTPS connections.",
            "B310": "Validate URLs before opening; prevent SSRF attacks.",
            "B311": "Use secrets module for cryptographic randomness, not random.",
            "B312": "Verify SSL certificates in telnet connections.",
            "B313": "Use defusedxml library to prevent XML attacks.",
            "B324": "Use SHA-256 or stronger; avoid MD5/SHA1 for security.",
            "B501": "Enable SSL certificate verification; set verify=True.",
            "B502": "Use modern TLS versions; avoid SSLv2/SSLv3.",
            "B503": "Use modern TLS versions; avoid calling ssl.wrap_socket without version.",
            "B504": "Enable certificate verification in ssl contexts.",
            "B505": "Use cryptographically secure key sizes (2048+ bits for RSA).",
            "B506": "Use PyYAML safe_load() instead of load() for untrusted data.",
            "B507": "Enable hostname verification in SSH connections.",
            "B601": "Avoid paramiko with shell=True; use explicit commands.",
            "B602": "Avoid subprocess with shell=True; use list arguments.",
            "B603": "Validate subprocess inputs; avoid user-controlled commands.",
            "B604": "Avoid shell functions; use subprocess with shell=False.",
            "B605": "Avoid os.system(); use subprocess with shell=False.",
            "B606": "Avoid os.popen(); use subprocess module.",
            "B607": "Use full paths for subprocess commands.",
            "B608": "Use parameterized queries; avoid string formatting in SQL.",
            "B609": "Avoid wildcard injection in shell commands.",
            "B610": "Avoid Django extra() and RawSQL with user input.",
            "B611": "Avoid Django RawSQL with user input.",
            "B701": "Avoid Jinja2 autoescape=False; enable autoescaping.",
            "B702": "Use Django's autoescape; avoid mark_safe() with user input.",
            "B703": "Use Django's autoescape; avoid SafeString with user input.",
        }
        return remediation_map.get(test_id, "Review and fix the identified security issue.")
