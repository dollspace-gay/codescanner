import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class PHPStanEngine(BaseEngine):
    name = "phpstan"
    description = "PHP static analysis tool"

    ERROR_SEVERITY = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.LOW,
    }

    SECURITY_PATTERNS = {
        "sql": ("CWE-89", Severity.CRITICAL, "SQL Injection"),
        "injection": ("CWE-74", Severity.CRITICAL, "Injection"),
        "xss": ("CWE-79", Severity.HIGH, "Cross-Site Scripting"),
        "eval": ("CWE-95", Severity.CRITICAL, "Code Injection"),
        "exec": ("CWE-78", Severity.CRITICAL, "Command Injection"),
        "shell": ("CWE-78", Severity.CRITICAL, "Command Injection"),
        "system": ("CWE-78", Severity.CRITICAL, "Command Injection"),
        "passthru": ("CWE-78", Severity.CRITICAL, "Command Injection"),
        "include": ("CWE-98", Severity.HIGH, "File Inclusion"),
        "require": ("CWE-98", Severity.HIGH, "File Inclusion"),
        "unserialize": ("CWE-502", Severity.CRITICAL, "Unsafe Deserialization"),
        "file_get_contents": ("CWE-73", Severity.MEDIUM, "File Access"),
        "file_put_contents": ("CWE-73", Severity.MEDIUM, "File Access"),
        "fopen": ("CWE-73", Severity.MEDIUM, "File Access"),
        "mysqli_query": ("CWE-89", Severity.HIGH, "SQL Query"),
        "mysql_query": ("CWE-89", Severity.HIGH, "SQL Query (deprecated)"),
        "preg_replace.*e": ("CWE-95", Severity.CRITICAL, "Code Execution via Regex"),
        "assert": ("CWE-95", Severity.HIGH, "Assert Code Execution"),
        "create_function": ("CWE-95", Severity.HIGH, "Dynamic Function Creation"),
        "call_user_func": ("CWE-470", Severity.MEDIUM, "Dynamic Function Call"),
        "extract": ("CWE-621", Severity.MEDIUM, "Variable Extraction"),
        "parse_str": ("CWE-621", Severity.MEDIUM, "Variable Parsing"),
        "header": ("CWE-113", Severity.MEDIUM, "HTTP Header"),
        "setcookie": ("CWE-614", Severity.MEDIUM, "Cookie Setting"),
        "md5": ("CWE-327", Severity.LOW, "Weak Hashing"),
        "sha1": ("CWE-327", Severity.LOW, "Weak Hashing"),
        "rand": ("CWE-330", Severity.LOW, "Weak Random"),
        "mt_rand": ("CWE-330", Severity.LOW, "Weak Random"),
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("phpstan")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "vendor/bin/phpstan",
            "./vendor/bin/phpstan",
            "/usr/bin/phpstan",
            "/usr/local/bin/phpstan",
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
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0 and "phpstan" in result.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _has_php_files(self, files: list[Path]) -> bool:
        return any(f.suffix.lower() == ".php" for f in files)

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        if not self._has_php_files(files):
            self.log("No PHP files detected, skipping PHPStan")
            return []

        self.log(f"Running PHPStan analysis on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("PHPStan executable not found")
            return []

        try:
            cmd = [
                exe,
                "analyse",
                "--error-format=json",
                "--no-progress",
                "--no-interaction",
            ]

            phpstan_config = target_path / "phpstan.neon"
            phpstan_dist = target_path / "phpstan.neon.dist"

            if phpstan_config.exists():
                cmd.extend(["-c", str(phpstan_config)])
            elif phpstan_dist.exists():
                cmd.extend(["-c", str(phpstan_dist)])
            else:
                cmd.extend(["--level", "5"])
                cmd.append(str(target_path))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(target_path),
                timeout=300,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("PHPStan analysis timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"PHPStan error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse PHPStan JSON output")
            return []

        files_data = data.get("files", {})

        for file_path_str, file_data in files_data.items():
            messages = file_data.get("messages", [])

            for msg in messages:
                message = msg.get("message", "")
                line = msg.get("line")
                identifier = msg.get("identifier", "")

                security_info = self._check_security_relevance(message)

                if security_info:
                    cwe_id, severity, issue_type = security_info
                else:
                    cwe_id = None
                    severity = Severity.MEDIUM
                    issue_type = "Code Quality"

                if file_path_str:
                    file_path = Path(file_path_str)
                    if not file_path.is_absolute():
                        file_path = target_path / file_path_str
                else:
                    file_path = target_path

                finding = Finding(
                    title=f"PHPStan: {issue_type}",
                    description=message,
                    severity=severity,
                    file_path=file_path,
                    line_number=line,
                    cwe_id=cwe_id,
                    tool=self.name,
                    confidence="high",
                    remediation=self._get_remediation(message, issue_type),
                )
                findings.append(finding)

        self.log(f"Found {len(findings)} PHP issues")
        return findings

    def _check_security_relevance(self, message: str) -> Optional[tuple]:
        message_lower = message.lower()

        for pattern, (cwe, severity, issue_type) in self.SECURITY_PATTERNS.items():
            if pattern in message_lower:
                return (cwe, severity, issue_type)

        return None

    def _get_remediation(self, message: str, issue_type: str) -> str:
        message_lower = message.lower()

        if "sql" in message_lower:
            return "Use prepared statements with parameterized queries (PDO or mysqli prepared statements)."
        elif "eval" in message_lower:
            return "Remove eval() usage. Use safer alternatives like json_decode() or explicit conditionals."
        elif "exec" in message_lower or "shell" in message_lower or "system" in message_lower:
            return "Avoid shell commands with user input. Use escapeshellarg() and escapeshellcmd() if necessary."
        elif "include" in message_lower or "require" in message_lower:
            return "Use a whitelist of allowed files. Never include files based on user input."
        elif "unserialize" in message_lower:
            return "Use json_decode() instead of unserialize() for untrusted data."
        elif "xss" in message_lower or "echo" in message_lower:
            return "Use htmlspecialchars() or htmlentities() when outputting user data."
        elif "md5" in message_lower or "sha1" in message_lower:
            return "Use password_hash() for passwords, or hash('sha256') for general hashing."
        elif "rand" in message_lower:
            return "Use random_bytes() or random_int() for security-sensitive random values."
        elif "cookie" in message_lower:
            return "Set secure and httponly flags: setcookie($name, $value, ['secure' => true, 'httponly' => true])"
        else:
            return "Review and fix the reported issue according to PHP security best practices."
