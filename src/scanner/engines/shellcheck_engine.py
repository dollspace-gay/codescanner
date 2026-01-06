import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class ShellCheckEngine(BaseEngine):
    name = "shellcheck"
    description = "Shell script static analysis tool"

    SEVERITY_MAP = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.LOW,
        "style": Severity.INFO,
    }

    SHELL_EXTENSIONS = {".sh", ".bash", ".ksh", ".zsh"}
    SHELL_FILENAMES = {"bashrc", ".bashrc", ".bash_profile", ".zshrc", ".profile"}

    CWE_MAP = {
        "SC1000": "CWE-398",  # Parsing error
        "SC2086": "CWE-78",   # Word splitting - command injection risk
        "SC2091": "CWE-78",   # Command injection
        "SC2046": "CWE-78",   # Quote to prevent word splitting
        "SC2034": "CWE-563",  # Unused variable
        "SC2006": "CWE-676",  # Use $() instead of legacy backticks
        "SC2064": "CWE-78",   # Trap expansion
        "SC2068": "CWE-78",   # Double quote array expansions
        "SC2145": "CWE-78",   # Array element access
        "SC2154": "CWE-457",  # Referenced but not assigned
        "SC2155": "CWE-457",  # Declare and assign separately
        "SC2164": "CWE-252",  # Use cd ... || exit
        "SC2181": "CWE-252",  # Check exit code directly
        "SC2029": "CWE-78",   # SSH command injection
        "SC2087": "CWE-78",   # Heredoc with variable expansion
        "SC2116": "CWE-561",  # Useless echo
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("shellcheck")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/shellcheck",
            "/usr/local/bin/shellcheck",
            "/opt/homebrew/bin/shellcheck",
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
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _is_shell_script(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.SHELL_EXTENSIONS:
            return True
        if file_path.name.lower() in self.SHELL_FILENAMES:
            return True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                if first_line.startswith("#!"):
                    shebang = first_line.lower()
                    if any(shell in shebang for shell in ["bash", "sh", "zsh", "ksh"]):
                        return True
        except (OSError, UnicodeDecodeError):
            return False

        return False

    def _get_shell_files(self, files: list[Path]) -> list[Path]:
        return [f for f in files if self._is_shell_script(f)]

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        shell_files = self._get_shell_files(files)

        if not shell_files:
            self.log("No shell scripts detected, skipping ShellCheck")
            return []

        self.log(f"Running ShellCheck on {len(shell_files)} shell scripts")

        exe = self._find_executable()
        if not exe:
            self.log("ShellCheck executable not found")
            return []

        all_findings: list[Finding] = []

        batch_size = 50
        for i in range(0, len(shell_files), batch_size):
            batch = shell_files[i:i + batch_size]
            file_args = [str(f) for f in batch]

            try:
                result = subprocess.run(
                    [exe, "--format=json", "--severity=style", *file_args],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if result.stdout:
                    findings = self._parse_results(result.stdout, target_path)
                    all_findings.extend(findings)

            except subprocess.TimeoutExpired:
                self.log(f"ShellCheck timed out on batch {i // batch_size + 1}")
            except subprocess.SubprocessError as e:
                self.log(f"ShellCheck error: {e}")

        self.log(f"Found {len(all_findings)} shell script issues")
        return all_findings

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse ShellCheck JSON output")
            return []

        if not isinstance(data, list):
            return []

        for issue in data:
            code = issue.get("code", 0)
            level = issue.get("level", "warning")
            message = issue.get("message", "Unknown issue")
            file_path_str = issue.get("file", "")
            line = issue.get("line")
            end_line = issue.get("endLine")
            column = issue.get("column")

            severity = self.SEVERITY_MAP.get(level, Severity.MEDIUM)

            sc_code = f"SC{code}"
            cwe_id = self.CWE_MAP.get(sc_code)

            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = target_path / file_path_str
            else:
                file_path = target_path

            description = f"{message}"
            if column:
                description += f" (column {column})"

            finding = Finding(
                title=f"{sc_code}: {self._get_issue_title(code)}",
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line,
                end_line=end_line,
                cwe_id=cwe_id,
                tool=self.name,
                confidence="high",
                remediation=self._get_remediation(code),
            )
            findings.append(finding)

        return findings

    def _get_issue_title(self, code: int) -> str:
        titles = {
            1000: "Parsing error",
            2006: "Use $(...) instead of backticks",
            2029: "SSH command injection risk",
            2034: "Unused variable",
            2046: "Quote to prevent word splitting",
            2064: "Trap expansion issue",
            2068: "Double quote array expansions",
            2086: "Double quote to prevent globbing",
            2087: "Heredoc variable expansion",
            2091: "Command result used as command",
            2116: "Useless echo",
            2145: "Array reference in concatenation",
            2154: "Variable referenced but not assigned",
            2155: "Declare and assign separately",
            2164: "Use 'cd ... || exit'",
            2181: "Check exit code directly",
        }
        return titles.get(code, "Shell script issue")

    def _get_remediation(self, code: int) -> str:
        remediations = {
            2006: "Replace backticks with $() for command substitution. $() is more readable and can be nested.",
            2029: "Quote the SSH command to prevent local expansion. Use single quotes or escape variables.",
            2034: "Remove the unused variable or use it. Prefix with underscore if intentionally unused.",
            2046: "Quote the command substitution to prevent word splitting: \"$(command)\"",
            2064: "Use single quotes for trap commands, or escape variables that should expand at trap time.",
            2068: "Use \"${array[@]}\" instead of ${array[@]} to properly handle elements with spaces.",
            2086: "Double quote the variable: \"$var\" to prevent word splitting and globbing.",
            2087: "Quote the heredoc delimiter to prevent variable expansion, or escape the variables.",
            2091: "Don't use $() as a condition. Use 'if command; then' or check exit status.",
            2116: "Remove useless echo. Use the command output directly instead.",
            2145: "Use proper array indexing: ${array[0]} or \"${array[@]}\" for all elements.",
            2154: "Initialize the variable before use or check if it's set with ${var:-default}.",
            2155: "Declare the variable on one line, then assign on another to catch assignment errors.",
            2164: "Add '|| exit' after cd to handle failures: cd /path || exit 1",
            2181: "Instead of checking $?, use 'if command; then' directly.",
        }
        return remediations.get(
            code,
            "Review the ShellCheck documentation for this code at https://www.shellcheck.net/wiki/"
        )
